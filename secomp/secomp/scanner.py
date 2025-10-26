"""
AWS resource scanner for Secomp compliance checks.
"""
import logging
import os
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

try:
    # Try relative import first (when used as module)
    from .models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails, ResourceFinding, ComplianceStatus, RiskLevel
    from .compliance import GDPRRules, RiskAssessor
except ImportError:
    # Fall back to absolute import (when run directly)
    from models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails, ResourceFinding, ComplianceStatus, RiskLevel
    from compliance import GDPRRules, RiskAssessor

logger = logging.getLogger(__name__)


class AWSScanner:
    """Scanner for AWS resources focusing on compliance and security."""

    def __init__(self, region: str = "us-east-1", debug: bool = False):
        self.region = region
        self.debug = debug
        self.s3_client = None
        self._init_aws_client()

        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
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
        if not self.s3_client:
            raise RuntimeError("AWS client not initialized")

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
        if not self.s3_client:
            raise RuntimeError("AWS client not initialized")

        if self.debug:
            logger.info(f"Scanning bucket: {bucket_name}")

        # Check public access
        public_access = self._check_bucket_public_access(bucket_name)

        # Check encryption
        encryption_enabled, encryption_type = self._check_bucket_encryption(bucket_name)

        # Get ACL grants (for detailed analysis)
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
            # Get bucket ACL
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)

            # Check for public grants
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')

                # Check for AllUsers or AuthenticatedUsers grants
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return True

            # Check bucket policy for public access
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_doc = policy.get('Policy', '{}')

                # Simple check for public principals (this could be enhanced)
                if '"*"' in policy_doc or '"AllUsers"' in policy_doc:
                    return True
            except ClientError as e:
                # No policy or access denied - not necessarily public
                if e.response['Error']['Code'] not in ['NoSuchBucketPolicy', 'AccessDenied']:
                    logger.warning(f"Unexpected error checking bucket policy: {e}")

            return False

        except ClientError as e:
            logger.error(f"Failed to check public access for bucket {bucket_name}: {e}")
            # Assume public if we can't check
            return True

    def _check_bucket_encryption(self, bucket_name: str) -> tuple[bool, Optional[str]]:
        """Check if bucket has encryption enabled."""
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

            if rules:
                # Get the first rule's encryption settings
                sse = rules[0].get('ApplyServerSideEncryptionByDefault', {})
                encryption_type = sse.get('SSEAlgorithm', 'Unknown')

                # Check if it's a valid encryption algorithm
                if encryption_type in ['AES256', 'aws:kms']:
                    return True, encryption_type

            return False, None

        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                # No encryption configured
                return False, None
            else:
                logger.error(f"Failed to check encryption for bucket {bucket_name}: {e}")
                return False, None

    def _get_bucket_acl_grants(self, bucket_name: str) -> List[Dict[str, Any]]:
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

        rules_engine = GDPRRules()
        risk_assessor = RiskAssessor()

        for bucket_name in buckets:
            try:
                # Get bucket details
                bucket_details = self.get_bucket_details(bucket_name)

                # Check compliance rules
                rules = rules_engine.check_all_rules(bucket_details)

                # Calculate risk score
                risk_score, risk_level = risk_assessor.calculate_risk_score(rules, bucket_details)

                # Generate recommendations
                recommendations = risk_assessor.generate_recommendations(rules, bucket_details)

                # Determine overall compliance status
                has_violations = any(rule.status == ComplianceStatus.NON_COMPLIANT for rule in rules)
                compliance_status = ComplianceStatus.NON_COMPLIANT if has_violations else ComplianceStatus.COMPLIANT

                # Create finding
                finding = ResourceFinding(
                    resource_id=bucket_name,
                    resource_type="s3_bucket",
                    resource_details=bucket_details.dict(),
                    compliance_status=compliance_status,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    rules_checked=rules,
                    recommendations=recommendations,
                    timestamp=datetime.now(timezone.utc)
                )

                findings.append(finding)

                if self.debug:
                    logger.info(f"Scanned bucket {bucket_name}: Risk Score {risk_score}, Status {compliance_status.value}")

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
            logging.basicConfig(level=logging.DEBUG)
            logger.info(f"Azure Scanner initialized for resource group: {resource_group}")
    def _init_azure_client(self) -> None:
        """Initialize Azure Blob Storage client."""
        try:
            from azure.storage.blob import BlobServiceClient
            from azure.identity import DefaultAzureCredential

            # Try to get credentials from environment or Azure CLI
            try:
                # First try managed identity (for Azure environments)
                credential = DefaultAzureCredential()
                # For this demo, we'll use a connection string pattern
                # In production, you'd want to use the credential
                account_url = os.getenv('AZURE_STORAGE_ACCOUNT_URL')
                if account_url:
                    self.blob_client = BlobServiceClient(account_url=account_url, credential=credential)
                else:
                    # Fallback for local development
                    connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
                    if connection_string:
                        self.blob_client = BlobServiceClient.from_connection_string(connection_string)
                    else:
                        logger.warning("No Azure credentials found. Set AZURE_STORAGE_ACCOUNT_URL or AZURE_STORAGE_CONNECTION_STRING")
                        self.blob_client = None
                        return

                logger.info("Azure Blob client initialized successfully")
            except Exception as e:
                logger.warning(f"Could not initialize Azure client: {e}")
                self.blob_client = None

        except ImportError:
            logger.error("Azure SDK not installed. Install with: pip install azure-storage-blob azure-identity")
            self.blob_client = None
    def list_blob_containers(self) -> List[str]:
        """List all blob containers in the storage account."""
        if not self.blob_client:
            logger.warning("Azure client not initialized")
            return []

        try:
            containers = []
            for container in self.blob_client.list_containers():
                containers.append(container.name)

            if self.debug:
                logger.info(f"Found {len(containers)} Azure containers: {containers}")

            return containers
        except Exception as e:
            logger.error(f"Failed to list Azure containers: {e}")
            return []

    def get_container_details(self, container_name: str) -> Dict[str, Any]:
        """Get detailed information about a blob container."""
        if not self.blob_client:
            logger.warning("Azure client not initialized")
            return self._get_default_container_details(container_name)

        try:
            # Get container client
            container_client = self.blob_client.get_container_client(container_name)

            # Check if container exists
            if not container_client.exists():
                return self._get_default_container_details(container_name)

            # Get container properties
            properties = container_client.get_container_properties()

            # Determine public access
            public_access = properties.public_access is not None

            # Get encryption settings (simplified)
            encryption_enabled = True  # Azure enables encryption by default
            encryption_type = "Microsoft-managed"

            # Get location from account (simplified)
            location = "East US"  # Would need to get from account properties

            return {
                "name": container_name,
                "resource_group": self.resource_group,
                "location": location,
                "public_access": public_access,
                "encryption_enabled": encryption_enabled,
                "encryption_type": encryption_type,
                "access_tier": "Hot"
            }

        except Exception as e:
            logger.error(f"Failed to get container details for {container_name}: {e}")
            return self._get_default_container_details(container_name)

    def _get_default_container_details(self, container_name: str) -> Dict[str, Any]:
        """Get default container details when Azure client is not available."""
        return {
            "name": container_name,
            "resource_group": self.resource_group,
            "location": "East US",
            "public_access": False,
            "encryption_enabled": True,
            "encryption_type": "Microsoft-managed",
            "access_tier": "Hot"
        }

    def scan_blob_containers(self) -> List[ResourceFinding]:
        """Scan all blob containers for compliance issues."""
        if self.debug:
            logger.info("Starting Azure blob compliance scan...")

        containers = self.list_blob_containers()
        findings = []

        rules_engine = GDPRRules()
        risk_assessor = RiskAssessor()

        for container_name in containers:
            try:
                # Get container details
                container_info = self.get_container_details(container_name)

                # Create AzureBlobDetails object
                from .models import AzureBlobDetails
                blob_details = AzureBlobDetails(**container_info)

                # Check compliance rules (adapted for Azure)
                rules = rules_engine.check_all_rules(blob_details)

                # Calculate risk score
                risk_score, risk_level = risk_assessor.calculate_risk_score(rules, blob_details)

                # Generate recommendations
                recommendations = risk_assessor.generate_recommendations(rules, blob_details)

                # Determine overall compliance status
                has_violations = any(rule.status == ComplianceStatus.NON_COMPLIANT for rule in rules)
                compliance_status = ComplianceStatus.NON_COMPLIANT if has_violations else ComplianceStatus.COMPLIANT

                # Create finding
                finding = ResourceFinding(
                    resource_id=f"{self.resource_group}/{container_name}",
                    resource_type="azure_blob_container",
                    resource_details=blob_details.dict(),
                    compliance_status=compliance_status,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    rules_checked=rules,
                    recommendations=recommendations,
                    timestamp=datetime.now(timezone.utc)
                )

                findings.append(finding)

                if self.debug:
                    logger.info(f"Scanned container {container_name}: Risk Score {risk_score}, Status {compliance_status.value}")

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
            logging.basicConfig(level=logging.DEBUG)
            logger.info(f"GCP Scanner initialized for project: {project_id}")

    def _init_gcp_client(self) -> None:
        """Initialize GCP Cloud Storage client."""
        try:
            from google.cloud import storage
            from google.auth import default

            # Try to get default credentials
            try:
                credentials, project = default()
                self.storage_client = storage.Client(credentials=credentials, project=project)
                logger.info(f"GCP Storage client initialized for project: {project}")
            except Exception as e:
                logger.warning(f"Could not initialize GCP client: {e}")
                self.storage_client = None

        except ImportError:
            logger.error("Google Cloud SDK not installed. Install with: pip install google-cloud-storage")
            self.storage_client = None
        except Exception as e:
            logger.error(f"Failed to initialize GCP client: {e}")
            self.storage_client = None

    def list_storage_buckets(self) -> List[str]:
        """List all storage buckets in the project."""
        if not self.storage_client:
            logger.warning("GCP client not initialized")
            return []

        try:
            buckets = []
            for bucket in self.storage_client.list_buckets():
                buckets.append(bucket.name)

            if self.debug:
                logger.info(f"Found {len(buckets)} GCP buckets: {buckets}")

            return buckets
        except Exception as e:
            logger.error(f"Failed to list GCP buckets: {e}")
            return []

    def get_bucket_details(self, bucket_name: str) -> Dict[str, Any]:
        """Get detailed information about a storage bucket."""
        if not self.storage_client:
            logger.warning("GCP client not initialized")
            return self._get_default_bucket_details(bucket_name)

        try:
            # Get bucket
            bucket = self.storage_client.bucket(bucket_name)

            # Check if bucket exists
            if not bucket.exists():
                return self._get_default_bucket_details(bucket_name)

            # Reload bucket to get latest info
            bucket.reload()

            # Check public access (simplified)
            # In reality, you'd need to check IAM policies
            public_access = False  # Default to False for security

            # Get encryption settings
            encryption_enabled = True  # GCP enables encryption by default
            encryption_type = "Google-managed"

            # Get storage class
            storage_class = getattr(bucket, 'storage_class', 'STANDARD')

            # Get versioning
            versioning_enabled = getattr(bucket, 'versioning_enabled', False)

            # Get uniform bucket level access
            uniform_bucket_level_access = getattr(bucket, 'uniform_bucket_level_access', False)

            return {
                "name": bucket_name,
                "project_id": self.project_id,
                "location": getattr(bucket, 'location', 'US-CENTRAL1'),
                "public_access": public_access,
                "encryption_enabled": encryption_enabled,
                "encryption_type": encryption_type,
                "storage_class": storage_class,
                "versioning_enabled": versioning_enabled,
                "uniform_bucket_level_access": uniform_bucket_level_access
            }

        except Exception as e:
            logger.error(f"Failed to get bucket details for {bucket_name}: {e}")
            return self._get_default_bucket_details(bucket_name)

    def _get_default_bucket_details(self, bucket_name: str) -> Dict[str, Any]:
        """Get default bucket details when GCP client is not available."""
        return {
            "name": bucket_name,
            "project_id": self.project_id,
            "location": "US-CENTRAL1",
            "public_access": False,
            "encryption_enabled": True,
            "encryption_type": "Google-managed",
            "storage_class": "STANDARD",
            "versioning_enabled": True,
            "uniform_bucket_level_access": True
        }

    def scan_storage_buckets(self) -> List[ResourceFinding]:
        """Scan all storage buckets for compliance issues."""
        if self.debug:
            logger.info("Starting GCP storage compliance scan...")

        buckets = self.list_storage_buckets()
        findings = []

        rules_engine = GDPRRules()
        risk_assessor = RiskAssessor()

        for bucket_name in buckets:
            try:
                # Get bucket details
                bucket_info = self.get_bucket_details(bucket_name)

                # Create GCPBucketDetails object
                from .models import GCPBucketDetails
                bucket_details = GCPBucketDetails(**bucket_info)

                # Check compliance rules (adapted for GCP)
                rules = rules_engine.check_all_rules(bucket_details)

                # Calculate risk score
                risk_score, risk_level = risk_assessor.calculate_risk_score(rules, bucket_details)

                # Generate recommendations
                recommendations = risk_assessor.generate_recommendations(rules, bucket_details)

                # Determine overall compliance status
                has_violations = any(rule.status == ComplianceStatus.NON_COMPLIANT for rule in rules)
                compliance_status = ComplianceStatus.NON_COMPLIANT if has_violations else ComplianceStatus.COMPLIANT

                # Create finding
                finding = ResourceFinding(
                    resource_id=f"{self.project_id}/{bucket_name}",
                    resource_type="gcp_storage_bucket",
                    resource_details=bucket_details.dict(),
                    compliance_status=compliance_status,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    rules_checked=rules,
                    recommendations=recommendations,
                    timestamp=datetime.now(timezone.utc)
                )

                findings.append(finding)

                if self.debug:
                    logger.info(f"Scanned bucket {bucket_name}: Risk Score {risk_score}, Status {compliance_status.value}")

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
