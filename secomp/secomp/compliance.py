"""
GDPR compliance rules and risk assessment logic for Secomp.
"""
import logging
from typing import Dict, List, Any, Optional
try:
    # Try relative import first (when used as module)
    from .models import ComplianceStatus, ComplianceRule, RiskLevel, S3BucketDetails, AzureBlobDetails, GCPBucketDetails
except ImportError:
    # Fall back to absolute import (when run directly)
    from models import ComplianceStatus, ComplianceRule, RiskLevel, S3BucketDetails, AzureBlobDetails, GCPBucketDetails

logger = logging.getLogger(__name__)


class GDPRRules:
    """GDPR compliance rules for multi-cloud resources."""

    def __init__(self):
        self.rules = {
            "GDPR-STORAGE-001": {
                "name": "Storage Public Access Block",
                "description": "Storage containers/buckets should not allow public access to prevent unauthorized data exposure",
                "weight": 50  # Risk score contribution
            },
            "GDPR-STORAGE-002": {
                "name": "Storage Encryption at Rest",
                "description": "Storage containers/buckets should have encryption enabled to protect data at rest",
                "weight": 30  # Risk score contribution
            },
            "GDPR-STORAGE-003": {
                "name": "Storage Access Logging",
                "description": "Storage containers/buckets should have access logging enabled for audit purposes",
                "weight": 20  # Risk score contribution
            }
        }

    def check_storage_public_access(self, resource_details: Any) -> ComplianceRule:
        """Check if storage resource has public access blocked."""
        rule_id = "GDPR-STORAGE-001"

        # Handle different resource types
        if hasattr(resource_details, 'public_access'):
            public_access = resource_details.public_access
        else:
            public_access = False  # Assume compliant if we can't check

        if public_access:
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

        # Handle different resource types
        if hasattr(resource_details, 'encryption_enabled'):
            encryption_enabled = resource_details.encryption_enabled
        else:
            encryption_enabled = False  # Assume non-compliant if we can't check

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
        """Check if storage resource has access logging enabled."""
        rule_id = "GDPR-STORAGE-003"

        # For MVP, we'll assume logging is not configured (placeholder)
        # In a real implementation, this would check CloudTrail, Azure Monitor, or Cloud Logging
        status = ComplianceStatus.UNKNOWN
        details = "Access logging configuration not checked in MVP"
        remediation = "Enable access logging for audit compliance"

        return ComplianceRule(
            rule_id=rule_id,
            rule_name=self.rules[rule_id]["name"],
            description=self.rules[rule_id]["description"],
            status=status,
            details=details,
            remediation=remediation
        )

    def check_all_rules(self, resource_details: Any) -> List[ComplianceRule]:
        """Check all GDPR rules for any storage resource."""
        rules = []
        rules.append(self.check_storage_public_access(resource_details))
        rules.append(self.check_storage_encryption(resource_details))
        rules.append(self.check_storage_access_logging(resource_details))
        return rules


class RiskAssessor:
    """AI-driven risk assessment (placeholder with heuristics)."""

    def __init__(self):
        # Placeholder for AI model - in future versions this could use Hugging Face
        self.risk_weights = {
            "public_access": 50,
            "no_encryption": 30,
            "unknown_logging": 20,
            "multiple_violations": 15
        }

    def calculate_risk_score(self, rules: List[ComplianceRule], resource_details: Any) -> tuple[int, RiskLevel]:
        """Calculate risk score based on compliance rules and bucket details."""
        score = 0
        violations = 0

        for rule in rules:
            if rule.status == ComplianceStatus.NON_COMPLIANT:
                rule_id = rule.rule_id
                if "001" in rule_id:  # Public access rule
                    score += self.risk_weights["public_access"]
                elif "002" in rule_id:  # Encryption rule
                    score += self.risk_weights["no_encryption"]
                violations += 1
            elif rule.status == ComplianceStatus.UNKNOWN:
                score += self.risk_weights["unknown_logging"]

        # Bonus penalty for multiple violations
        if violations > 1:
            score += self.risk_weights["multiple_violations"] * violations

        # Cap at 100
        score = min(score, 100)

        # Determine risk level
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

        # Check for public access
        if hasattr(resource_details, 'public_access') and resource_details.public_access:
            recommendations.append("Conduct immediate security audit of resource contents")

        if not recommendations:
            recommendations.append("No immediate actions required - maintain current security posture")

        return recommendations


def load_rego_policy(policy_path: str) -> Optional[Dict[str, Any]]:
    """Placeholder for Open Policy Agent (OPA) Rego policy loading."""
    # In future versions, this would load and compile Rego policies
    logger.info(f"Loading Rego policy from {policy_path} (placeholder)")
    return {"status": "placeholder", "message": "OPA integration planned for v0.2.0"}
