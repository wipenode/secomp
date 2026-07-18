"""
Multi-cloud resource scanners for Secomp compliance checks.
"""
import logging
import os
from typing import List, Optional, Tuple
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from .models import (
    S3BucketDetails,
    AzureBlobDetails,
    GCPBucketDetails,
    ResourceFinding,
    ComplianceStatus,
)
from .compliance import GDPRRules, RiskAssessor

logger = logging.getLogger(__name__)


def _build_finding(resource_id: str, resource_type: str, details_model) -> ResourceFinding:
    """Run compliance rules and risk assessment for a resource and build a finding."""
    rules_engine = GDPRRules()
    risk_assessor = RiskAssessor()

    rules = rules_engine.check_all_rules(details_model)
    risk_score, risk_level = risk_assessor.calculate_risk_score(rules, details_model)
    recommendations = risk_assessor.generate_recommendations(rules, details_model)

    has_violations = any(rule.status == ComplianceStatus.NON_COMPLIANT for rule in rules)
    compliance_status = ComplianceStatus.NON_COMPLIANT if has_violations else ComplianceStatus.COMPLIANT

    return ResourceFinding(
        resource_id=resource_id,
        resource_type=resource_type,
        resource_details=details_model.model_dump(),
        compliance_status=compliance_status,
        risk_score=risk_score,
        risk_level=risk_level,
        rules_checked=rules,
        recommendations=recommendations,
        timestamp=datetime.now(timezone.utc),
    )


class AWSScanner:
    """Scanner for AWS resources focusing on compliance and security."""

    def __init__(self, region: str = "us-east-1", debug: bool = False):
        self.region = region
        self.debug = debug
        self.s3_client = None
        self._init_aws_client()

        if self.debug:
            logger.info(f"AWS Scanner initialized for region: {region}")

    def _init_aws_client(self) -> None:
        """Initialize AWS S3 client."""
        try:
            self.s3_client = boto3.client('s3', region_name=self.region)
            logger.info("AWS S3 client initialized successfully")
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error(f"AWS credentials missing or invalid: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS client: {e}")
            raise

    def list_s3_buckets(self) -> List[str]:
        """List all S3 buckets in the account."""
        try:
            response = self.s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]

            if self.debug:
                logger.info(f"Found {len(buckets)} S3 buckets: {buckets}")

            return buckets
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            raise

    def get_bucket_details(self, bucket_name: str) -> S3BucketDetails:
        """Get detailed information about an S3 bucket."""
        if self.debug:
            logger.info(f"Scanning bucket: {bucket_name}")

        public_access = self._check_bucket_public_access(bucket_name)
        encryption_enabled, encryption_type = self._check_bucket_encryption(bucket_name)
        acl_grants = self._get_bucket_acl_grants(bucket_name)

        return S3BucketDetails(
            name=bucket_name,
            region=self.region,
            public_access=public_access,
            encryption_enabled=encryption_enabled,
            encryption_type=encryption_type,
            acl_grants=acl_grants
        )

    def _check_bucket_public_access(self, bucket_name: str) -> bool:
        """Check if bucket has public access enabled."""
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)

            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')

                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return True

            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = policy.get('Policy', '{}')

                # Simple heuristic for public principals (could be enhanced
                # with proper policy document parsing)
                if '"Principal": "*"' in policy_doc or '"Principal":"*"' in policy_doc or '"AWS": "*"' in policy_doc:
                    return True
            except ClientError as e:
                # No policy or access denied - not necessarily public
                if e.response['Error']['Code'] not in ['NoSuchBucketPolicy', 'AccessDenied']:
                    logger.warning(f"Unexpected error checking bucket policy: {e}")

            return False

        except ClientError as e:
            logger.error(f"Failed to check public access for bucket {bucket_name}: {e}")
            # Fail closed: treat unverifiable buckets as public so they are surfaced
            return True

    def _check_bucket_encryption(self, bucket_name: str) -> Tuple[bool, Optional[str]]:
        """Check if bucket has encryption enabled."""
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

            if rules:
                sse = rules[0].get('ApplyServerSideEncryptionByDefault', {})
                encryption_type = sse.get('SSEAlgorithm', 'Unknown')

                if encryption_type in ['AES256', 'aws:kms', 'aws:kms:dsse']:
                    return True, encryption_type

            return False, None

        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return False, None
            logger.error(f"Failed to check encryption for bucket {bucket_name}: {e}")
            return False, None

    def _get_bucket_acl_grants(self, bucket_name: str) -> List[dict]:
        """Get detailed ACL grants for the bucket."""
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            return acl.get('Grants', [])
        except ClientError as e:
            logger.error(f"Failed to get ACL grants for bucket {bucket_name}: {e}")
            return []

    def scan_s3_buckets(self) -> List[ResourceFinding]:
        """Scan all S3 buckets for compliance issues."""
        if self.debug:
            logger.info("Starting S3 compliance scan...")

        buckets = self.list_s3_buckets()
        findings = []

        for bucket_name in buckets:
            try:
                bucket_details = self.get_bucket_details(bucket_name)
                finding = _build_finding(bucket_name, "s3_bucket", bucket_details)
                findings.append(finding)

                if self.debug:
                    logger.info(
                        f"Scanned bucket {bucket_name}: Risk Score {finding.risk_score}, "
                        f"Status {finding.compliance_status.value}"
                    )
            except Exception as e:
                logger.error(f"Failed to scan bucket {bucket_name}: {e}")
                # Continue with other buckets

        if self.debug:
            logger.info(f"Completed scan of {len(findings)} buckets")

        return findings


class AzureScanner:
    """Scanner for Azure Blob Storage resources."""

    def __init__(self, resource_group: str = "default", debug: bool = False):
        self.resource_group = resource_group
        self.debug = debug
        self.blob_client = None
        self._init_azure_client()

        if self.debug:
            logger.info(f"Azure Scanner initialized for resource group: {resource_group}")

    def _init_azure_client(self) -> None:
        """Initialize Azure Blob Storage client."""
        try:
            from azure.storage.blob import BlobServiceClient
            from azure.identity import DefaultAzureCredential
        except ImportError:
            logger.error("Azure SDK not installed. Install with: pip install secomp[azure]")
            return

        try:
            account_url = os.getenv('AZURE_STORAGE_ACCOUNT_URL')
            connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')

            if account_url:
                self.blob_client = BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())
            elif connection_string:
                self.blob_client = BlobServiceClient.from_connection_string(connection_string)
            else:
                logger.warning(
                    "No Azure credentials found. Set AZURE_STORAGE_ACCOUNT_URL or AZURE_STORAGE_CONNECTION_STRING"
                )
                return

            logger.info("Azure Blob client initialized successfully")
        except Exception as e:
            logger.warning(f"Could not initialize Azure client: {e}")
            self.blob_client = None

    def list_blob_containers(self) -> List[str]:
        """List all blob containers in the storage account."""
        if not self.blob_client:
            logger.warning("Azure client not initialized")
            return []

        try:
            containers = [container.name for container in self.blob_client.list_containers()]

            if self.debug:
                logger.info(f"Found {len(containers)} Azure containers: {containers}")

            return containers
        except Exception as e:
            logger.error(f"Failed to list Azure containers: {e}")
            return []

    def get_container_details(self, container_name: str) -> AzureBlobDetails:
        """Get detailed information about a blob container.

        Raises if the container cannot be inspected, so callers never receive
        fabricated (falsely compliant) data.
        """
        if not self.blob_client:
            raise RuntimeError("Azure client not initialized")

        container_client = self.blob_client.get_container_client(container_name)
        properties = container_client.get_container_properties()

        public_access = properties.public_access is not None

        return AzureBlobDetails(
            name=container_name,
            resource_group=self.resource_group,
            location=None,  # Requires ARM API (management plane), not available via data plane
            public_access=public_access,
            # Azure Storage always encrypts data at rest (SSE cannot be disabled)
            encryption_enabled=True,
            encryption_type="Microsoft-managed",
            access_tier="Hot",
        )

    def scan_blob_containers(self) -> List[ResourceFinding]:
        """Scan all blob containers for compliance issues."""
        if self.debug:
            logger.info("Starting Azure blob compliance scan...")

        containers = self.list_blob_containers()
        findings = []

        for container_name in containers:
            try:
                blob_details = self.get_container_details(container_name)
                finding = _build_finding(
                    f"{self.resource_group}/{container_name}", "azure_blob_container", blob_details
                )
                findings.append(finding)

                if self.debug:
                    logger.info(
                        f"Scanned container {container_name}: Risk Score {finding.risk_score}, "
                        f"Status {finding.compliance_status.value}"
                    )
            except Exception as e:
                logger.error(f"Failed to scan container {container_name}: {e}")

        if self.debug:
            logger.info(f"Completed scan of {len(findings)} containers")

        return findings


class GCPScanner:
    """Scanner for GCP Cloud Storage resources."""

    def __init__(self, project_id: str = "default-project", debug: bool = False):
        self.project_id = project_id
        self.debug = debug
        self.storage_client = None
        self._init_gcp_client()

        if self.debug:
            logger.info(f"GCP Scanner initialized for project: {project_id}")

    def _init_gcp_client(self) -> None:
        """Initialize GCP Cloud Storage client."""
        try:
            from google.cloud import storage
            from google.auth import default
        except ImportError:
            logger.error("Google Cloud SDK not installed. Install with: pip install secomp[gcp]")
            return

        try:
            credentials, project = default()
            self.storage_client = storage.Client(credentials=credentials, project=project or self.project_id)
            logger.info(f"GCP Storage client initialized for project: {project or self.project_id}")
        except Exception as e:
            logger.warning(f"Could not initialize GCP client: {e}")
            self.storage_client = None

    def list_storage_buckets(self) -> List[str]:
        """List all storage buckets in the project."""
        if not self.storage_client:
            logger.warning("GCP client not initialized")
            return []

        try:
            buckets = [bucket.name for bucket in self.storage_client.list_buckets()]

            if self.debug:
                logger.info(f"Found {len(buckets)} GCP buckets: {buckets}")

            return buckets
        except Exception as e:
            logger.error(f"Failed to list GCP buckets: {e}")
            return []

    def _check_bucket_public_access(self, bucket) -> bool:
        """Check bucket IAM policy for public principals."""
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", set())
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to check IAM policy for bucket {bucket.name}: {e}")
            # Fail closed: treat unverifiable buckets as public so they are surfaced
            return True

    def get_bucket_details(self, bucket_name: str) -> GCPBucketDetails:
        """Get detailed information about a storage bucket.

        Raises if the bucket cannot be inspected, so callers never receive
        fabricated (falsely compliant) data.
        """
        if not self.storage_client:
            raise RuntimeError("GCP client not initialized")

        bucket = self.storage_client.get_bucket(bucket_name)

        public_access = self._check_bucket_public_access(bucket)

        iam_config = bucket.iam_configuration
        uniform_access = bool(iam_config.uniform_bucket_level_access_enabled) if iam_config else False

        return GCPBucketDetails(
            name=bucket_name,
            project_id=self.project_id,
            location=bucket.location,
            public_access=public_access,
            # GCP always encrypts data at rest; type depends on key management
            encryption_enabled=True,
            encryption_type="Customer-managed" if bucket.default_kms_key_name else "Google-managed",
            storage_class=bucket.storage_class or "STANDARD",
            versioning_enabled=bool(bucket.versioning_enabled),
            uniform_bucket_level_access=uniform_access,
        )

    def scan_storage_buckets(self) -> List[ResourceFinding]:
        """Scan all storage buckets for compliance issues."""
        if self.debug:
            logger.info("Starting GCP storage compliance scan...")

        buckets = self.list_storage_buckets()
        findings = []

        for bucket_name in buckets:
            try:
                bucket_details = self.get_bucket_details(bucket_name)
                finding = _build_finding(
                    f"{self.project_id}/{bucket_name}", "gcp_storage_bucket", bucket_details
                )
                findings.append(finding)

                if self.debug:
                    logger.info(
                        f"Scanned bucket {bucket_name}: Risk Score {finding.risk_score}, "
                        f"Status {finding.compliance_status.value}"
                    )
            except Exception as e:
                logger.error(f"Failed to scan bucket {bucket_name}: {e}")

        if self.debug:
            logger.info(f"Completed scan of {len(findings)} buckets")

        return findings


def create_scanner(region: str = "us-east-1", debug: bool = False) -> AWSScanner:
    """Factory function to create an AWS scanner."""
    return AWSScanner(region=region, debug=debug)


def create_azure_scanner(resource_group: str = "default", debug: bool = False) -> AzureScanner:
    """Factory function to create an Azure scanner."""
    return AzureScanner(resource_group=resource_group, debug=debug)


def create_gcp_scanner(project_id: str = "default-project", debug: bool = False) -> GCPScanner:
    """Factory function to create a GCP scanner."""
    return GCPScanner(project_id=project_id, debug=debug)
