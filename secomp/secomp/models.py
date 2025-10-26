"""
Data models for Secomp compliance reports and scanning results.
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class S3BucketDetails(BaseModel):
    """Details about an S3 bucket."""
    name: str = Field(..., description="S3 bucket name")
    region: str = Field(..., description="AWS region")
    public_access: bool = Field(..., description="Whether bucket has public access")
    encryption_enabled: bool = Field(..., description="Whether bucket has encryption enabled")
    encryption_type: Optional[str] = Field(None, description="Type of encryption (AES256, etc.)")
    acl_grants: List[Dict[str, Any]] = Field(default_factory=list, description="ACL grants information")


class AzureBlobDetails(BaseModel):
    """Details about an Azure Blob Storage container."""
    name: str = Field(..., description="Blob container name")
    resource_group: str = Field(..., description="Azure resource group")
    location: str = Field(..., description="Azure region/location")
    public_access: bool = Field(..., description="Whether container has public access")
    encryption_enabled: bool = Field(..., description="Whether encryption is enabled")
    encryption_type: Optional[str] = Field(None, description="Type of encryption")
    access_tier: str = Field(default="Hot", description="Access tier (Hot/Cool/Archive)")


class GCPBucketDetails(BaseModel):
    """Details about a GCP Cloud Storage bucket."""
    name: str = Field(..., description="GCP bucket name")
    project_id: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP region/location")
    public_access: bool = Field(..., description="Whether bucket has public access")
    encryption_enabled: bool = Field(..., description="Whether encryption is enabled")
    encryption_type: Optional[str] = Field(None, description="Type of encryption (Google-managed or Customer-managed)")
    storage_class: str = Field(default="STANDARD", description="Storage class")
    versioning_enabled: bool = Field(..., description="Whether versioning is enabled")
    uniform_bucket_level_access: bool = Field(..., description="Whether uniform bucket-level access is enabled")


class ComplianceRule(BaseModel):
    """A compliance rule that was checked."""
    rule_id: str = Field(..., description="Unique rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="Rule description")
    status: ComplianceStatus = Field(..., description="Rule compliance status")
    details: Optional[str] = Field(None, description="Additional rule details")
    remediation: Optional[str] = Field(None, description="Remediation steps")


class ResourceFinding(BaseModel):
    """A finding for a specific resource."""
    resource_id: str = Field(..., description="Unique resource identifier")
    resource_type: str = Field(..., description="Type of resource (s3_bucket, etc.)")
    resource_details: Dict[str, Any] = Field(..., description="Detailed resource information")
    compliance_status: ComplianceStatus = Field(..., description="Overall compliance status")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk level")
    rules_checked: List[ComplianceRule] = Field(..., description="Rules that were checked")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the scan was performed")


class ComplianceReport(BaseModel):
    """Complete compliance report."""
    scan_id: str = Field(..., description="Unique scan identifier")
    cloud_provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    compliance_framework: str = Field(..., description="Compliance framework (gdpr, nis2, etc.)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the scan was performed")
    total_resources: int = Field(..., description="Total number of resources scanned")
    compliant_resources: int = Field(..., description="Number of compliant resources")
    non_compliant_resources: int = Field(..., description="Number of non-compliant resources")
    overall_risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    findings: List[ResourceFinding] = Field(..., description="Individual resource findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary statistics")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScanConfig(BaseModel):
    """Configuration for a compliance scan."""
    cloud_provider: str = Field(..., description="Cloud provider to scan")
    compliance_framework: str = Field(..., description="Compliance framework to check")
    regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="Regions to scan")
    resource_types: List[str] = Field(default_factory=lambda: ["s3"], description="Resource types to scan")
    output_format: str = Field(default="json", description="Output format")
    output_file: Optional[str] = Field(None, description="Output file path")
    debug: bool = Field(default=False, description="Enable debug mode")
