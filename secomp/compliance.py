"""
GDPR compliance rules and risk assessment logic for Secomp.
"""
import logging
from typing import Dict, List, Any, Optional, Tuple

from .models import ComplianceStatus, ComplianceRule, RiskLevel

logger = logging.getLogger(__name__)


class GDPRRules:
    """GDPR compliance rules for multi-cloud resources."""

    def __init__(self):
        self.rules = {
            "GDPR-STORAGE-001": {
                "name": "Storage Public Access Block",
                "description": "Storage containers/buckets should not allow public access to prevent unauthorized data exposure",
                "weight": 50,
            },
            "GDPR-STORAGE-002": {
                "name": "Storage Encryption at Rest",
                "description": "Storage containers/buckets should have encryption enabled to protect data at rest",
                "weight": 30,
            },
            "GDPR-STORAGE-003": {
                "name": "Storage Access Logging",
                "description": "Storage containers/buckets should have access logging enabled for audit purposes",
                "weight": 20,
            },
        }

    def check_storage_public_access(self, resource_details: Any) -> ComplianceRule:
        """Check if storage resource has public access blocked."""
        rule_id = "GDPR-STORAGE-001"

        public_access = getattr(resource_details, 'public_access', None)

        if public_access is None:
            status = ComplianceStatus.UNKNOWN
            details = "Public access state could not be determined"
            remediation = "Verify public access configuration manually"
        elif public_access:
            status = ComplianceStatus.NON_COMPLIANT
            details = "Storage resource allows public access"
            remediation = "Disable public access for the storage resource"
        else:
            status = ComplianceStatus.COMPLIANT
            details = "Storage resource public access is properly blocked"
            remediation = None

        return ComplianceRule(
            rule_id=rule_id,
            rule_name=self.rules[rule_id]["name"],
            description=self.rules[rule_id]["description"],
            status=status,
            details=details,
            remediation=remediation
        )

    def check_storage_encryption(self, resource_details: Any) -> ComplianceRule:
        """Check if storage resource has encryption enabled."""
        rule_id = "GDPR-STORAGE-002"

        encryption_enabled = getattr(resource_details, 'encryption_enabled', False)

        if not encryption_enabled:
            status = ComplianceStatus.NON_COMPLIANT
            details = "Storage resource does not have encryption enabled"
            remediation = "Enable encryption for the storage resource"
        else:
            status = ComplianceStatus.COMPLIANT
            encryption_type = getattr(resource_details, 'encryption_type', 'Unknown')
            details = f"Storage resource has {encryption_type} encryption enabled"
            remediation = None

        return ComplianceRule(
            rule_id=rule_id,
            rule_name=self.rules[rule_id]["name"],
            description=self.rules[rule_id]["description"],
            status=status,
            details=details,
            remediation=remediation
        )

    def check_storage_access_logging(self, resource_details: Any) -> ComplianceRule:
        """Check if storage resource has access logging enabled.

        MVP limitation: logging configuration is not yet checked (would require
        CloudTrail, Azure Monitor, or Cloud Logging integration).
        """
        rule_id = "GDPR-STORAGE-003"

        return ComplianceRule(
            rule_id=rule_id,
            rule_name=self.rules[rule_id]["name"],
            description=self.rules[rule_id]["description"],
            status=ComplianceStatus.UNKNOWN,
            details="Access logging configuration not checked in MVP",
            remediation="Enable access logging for audit compliance"
        )

    def check_all_rules(self, resource_details: Any) -> List[ComplianceRule]:
        """Check all GDPR rules for any storage resource."""
        return [
            self.check_storage_public_access(resource_details),
            self.check_storage_encryption(resource_details),
            self.check_storage_access_logging(resource_details),
        ]


class RiskAssessor:
    """Heuristic risk assessment based on rule weights."""

    # Score contribution per rule when it is violated / unknown
    RULE_WEIGHTS = {
        "GDPR-STORAGE-001": 50,
        "GDPR-STORAGE-002": 30,
        "GDPR-STORAGE-003": 20,
    }
    MULTIPLE_VIOLATIONS_PENALTY = 15
    # Rules whose UNKNOWN status still adds risk (unverifiable = risky)
    UNKNOWN_COUNTS_AS_RISK = {"GDPR-STORAGE-003"}

    def calculate_risk_score(self, rules: List[ComplianceRule], resource_details: Any) -> Tuple[int, RiskLevel]:
        """Calculate risk score based on compliance rules and resource details."""
        score = 0
        violations = 0

        for rule in rules:
            weight = self.RULE_WEIGHTS.get(rule.rule_id, 0)
            if rule.status == ComplianceStatus.NON_COMPLIANT:
                score += weight
                violations += 1
            elif rule.status == ComplianceStatus.UNKNOWN and rule.rule_id in self.UNKNOWN_COUNTS_AS_RISK:
                score += weight

        if violations > 1:
            score += self.MULTIPLE_VIOLATIONS_PENALTY * violations

        score = min(score, 100)

        if score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif score >= 60:
            risk_level = RiskLevel.HIGH
        elif score >= 30:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        return score, risk_level

    def generate_recommendations(self, rules: List[ComplianceRule], resource_details: Any) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []

        for rule in rules:
            if rule.status == ComplianceStatus.NON_COMPLIANT:
                if rule.rule_id == "GDPR-STORAGE-001":
                    recommendations.append("Immediately block public access to prevent data breaches")
                    recommendations.append("Review and remove any public access policies")
                elif rule.rule_id == "GDPR-STORAGE-002":
                    recommendations.append("Enable storage encryption")
                    recommendations.append("Consider using managed encryption keys")

        if getattr(resource_details, 'public_access', False):
            recommendations.append("Conduct immediate security audit of resource contents")

        if not recommendations:
            recommendations.append("No immediate actions required - maintain current security posture")

        return recommendations


def load_rego_policy(policy_path: str) -> Optional[Dict[str, Any]]:
    """Placeholder for Open Policy Agent (OPA) Rego policy loading."""
    logger.info(f"Loading Rego policy from {policy_path} (placeholder)")
    return {"status": "placeholder", "message": "OPA integration planned for v0.2.0"}
