"""
Unit tests for AWS scanner functionality using moto for mocking.
"""
import pytest
import boto3
from moto import mock_s3
from unittest.mock import patch

from secomp.scanner import AWSScanner, AzureScanner, GCPScanner
from secomp.models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails
from secomp.compliance import GDPRRules, RiskAssessor


@pytest.fixture
def mock_s3_client():
    """Create a mock S3 client."""
    with mock_s3():
        client = boto3.client('s3', region_name='us-east-1')
        yield client


@pytest.fixture
def scanner(mock_s3_client):
    """Create a scanner instance with mocked AWS."""
    return AWSScanner(region='us-east-1', debug=False)


class TestAWSScanner:
    """Test cases for AWS S3 scanner."""

    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.region == 'us-east-1'
        assert scanner.debug is False
        assert scanner.s3_client is not None

    def test_list_s3_buckets_empty(self, scanner):
        """Test listing buckets when none exist."""
        buckets = scanner.list_s3_buckets()
        assert buckets == []

    def test_list_s3_buckets_with_data(self, scanner, mock_s3_client):
        """Test listing buckets with mock data."""
        # Create mock buckets
        mock_s3_client.create_bucket(Bucket='test-bucket-1')
        mock_s3_client.create_bucket(Bucket='test-bucket-2')

        buckets = scanner.list_s3_buckets()
        assert len(buckets) == 2
        assert 'test-bucket-1' in buckets
        assert 'test-bucket-2' in buckets

    def test_get_bucket_details_public_bucket(self, scanner, mock_s3_client):
        """Test getting details of a public bucket."""
        bucket_name = 'public-test-bucket'
        mock_s3_client.create_bucket(Bucket=bucket_name)

        # Make bucket public by setting ACL
        mock_s3_client.put_bucket_acl(
            Bucket=bucket_name,
            ACL='public-read'
        )

        details = scanner.get_bucket_details(bucket_name)

        assert details.name == bucket_name
        assert details.public_access is True
        assert details.encryption_enabled is False

    def test_get_bucket_details_encrypted_bucket(self, scanner, mock_s3_client):
        """Test getting details of an encrypted bucket."""
        bucket_name = 'encrypted-test-bucket'
        mock_s3_client.create_bucket(Bucket=bucket_name)

        # Enable encryption
        mock_s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )

        details = scanner.get_bucket_details(bucket_name)

        assert details.name == bucket_name
        assert details.encryption_enabled is True
        assert details.encryption_type == 'AES256'

    def test_scan_s3_buckets_comprehensive(self, scanner, mock_s3_client):
        """Test comprehensive S3 bucket scanning."""
        # Create test buckets with different configurations
        public_bucket = 'public-bucket'
        private_bucket = 'private-bucket'

        mock_s3_client.create_bucket(Bucket=public_bucket)
        mock_s3_client.create_bucket(Bucket=private_bucket)

        # Configure public bucket
        mock_s3_client.put_bucket_acl(Bucket=public_bucket, ACL='public-read')

        # Configure private bucket with encryption
        mock_s3_client.put_bucket_encryption(
            Bucket=private_bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )

        findings = scanner.scan_s3_buckets()

        assert len(findings) == 2

        # Check public bucket finding
        public_finding = next(f for f in findings if f.resource_id == public_bucket)
        assert public_finding.compliance_status.value == 'non_compliant'
        assert public_finding.risk_score > 0
        assert len(public_finding.recommendations) > 0

        assert private_finding.compliance_status.value == 'compliant'
        assert private_finding.risk_score == 0 or private_finding.risk_score < 30


class TestAzureScanner:
    """Test cases for Azure Blob Storage scanner."""

    def test_azure_scanner_initialization(self):
        """Test Azure scanner initializes correctly."""
        scanner = AzureScanner(resource_group='test-rg', debug=False)
        assert scanner.resource_group == 'test-rg'
        assert scanner.debug is False

    def test_azure_list_blob_containers(self):
        """Test listing Azure blob containers."""
        scanner = AzureScanner(resource_group='test-rg', debug=True)
        containers = scanner.list_blob_containers()
        assert len(containers) == 2
        assert 'test-container-1' in containers
        assert 'test-container-2' in containers

    def test_azure_get_container_details(self):
        """Test getting Azure container details."""
        scanner = AzureScanner(resource_group='test-rg', debug=True)
        details = scanner.get_container_details('test-container-1')

        assert details['name'] == 'test-container-1'
        assert details['resource_group'] == 'test-rg'
        assert details['location'] == 'East US'
        assert details['public_access'] is False
        assert details['encryption_enabled'] is True

    def test_azure_scan_blob_containers(self):
        """Test comprehensive Azure blob container scanning."""
        scanner = AzureScanner(resource_group='test-rg', debug=True)
        findings = scanner.scan_blob_containers()

        assert len(findings) == 2

        # Check findings
        container1_finding = next(f for f in findings if 'test-container-1' in f.resource_id)
        assert container1_finding.compliance_status.value == 'compliant'
        assert container1_finding.risk_score == 0
        assert container1_finding.resource_type == 'azure_blob_container'


class TestGCPScanner:
    """Test cases for GCP Cloud Storage scanner."""

    def test_gcp_scanner_initialization(self):
        """Test GCP scanner initializes correctly."""
        scanner = GCPScanner(project_id='test-project', debug=False)
        assert scanner.project_id == 'test-project'
        assert scanner.debug is False

    def test_gcp_list_storage_buckets(self):
        """Test listing GCP storage buckets."""
        scanner = GCPScanner(project_id='test-project', debug=True)
        buckets = scanner.list_storage_buckets()
        assert len(buckets) == 2
        assert 'test-bucket-1' in buckets
        assert 'test-bucket-2' in buckets

    def test_gcp_get_bucket_details(self):
        """Test getting GCP bucket details."""
        scanner = GCPScanner(project_id='test-project', debug=True)
        details = scanner.get_bucket_details('test-bucket-1')

        assert details['name'] == 'test-bucket-1'
        assert details['project_id'] == 'test-project'
        assert details['location'] == 'US-CENTRAL1'
        assert details['public_access'] is False
        assert details['encryption_enabled'] is True
        assert details['versioning_enabled'] is True

    def test_gcp_scan_storage_buckets(self):
        """Test comprehensive GCP storage bucket scanning."""
        scanner = GCPScanner(project_id='test-project', debug=True)
        findings = scanner.scan_storage_buckets()

        assert len(findings) == 2

        # Check findings
        bucket1_finding = next(f for f in findings if 'test-bucket-1' in f.resource_id)
        assert bucket1_finding.compliance_status.value == 'compliant'
        assert bucket1_finding.risk_score == 0
        assert bucket1_finding.resource_type == 'gcp_storage_bucket'


class TestMultiCloudCompliance:
    """Test compliance rules across multiple cloud providers."""

    def test_compliance_rules_azure_blob(self):
        """Test GDPR compliance rules for Azure Blob."""
        rules = GDPRRules()

        # Test compliant Azure blob
        azure_blob = AzureBlobDetails(
            name='compliant-container',
            resource_group='test-rg',
            location='East US',
            public_access=False,
            encryption_enabled=True,
            encryption_type='Microsoft-managed',
            access_tier='Hot'
        )

        all_rules = rules.check_all_rules(azure_blob)

        assert len(all_rules) == 3
        rule_ids = [rule.rule_id for rule in all_rules]
        assert 'GDPR-STORAGE-001' in rule_ids
        assert 'GDPR-STORAGE-002' in rule_ids
        assert 'GDPR-STORAGE-003' in rule_ids

        # Should be compliant
        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'compliant'
        assert encryption_rule.status.value == 'compliant'

    def test_compliance_rules_gcp_bucket(self):
        """Test GDPR compliance rules for GCP Storage."""
        rules = GDPRRules()

        # Test compliant GCP bucket
        gcp_bucket = GCPBucketDetails(
            name='compliant-bucket',
            project_id='test-project',
            location='US-CENTRAL1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='Google-managed',
            storage_class='STANDARD',
            versioning_enabled=True,
            uniform_bucket_level_access=True
        )

        all_rules = rules.check_all_rules(gcp_bucket)

        assert len(all_rules) == 3
        rule_ids = [rule.rule_id for rule in all_rules]
        assert 'GDPR-STORAGE-001' in rule_ids
        assert 'GDPR-STORAGE-002' in rule_ids
        assert 'GDPR-STORAGE-003' in rule_ids

        # Should be compliant
        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'compliant'
        assert encryption_rule.status.value == 'compliant'

    def test_compliance_rules_non_compliant_azure(self):
        """Test non-compliant Azure blob."""
        rules = GDPRRules()

        # Test non-compliant Azure blob
        azure_blob = AzureBlobDetails(
            name='non-compliant-container',
            resource_group='test-rg',
            location='East US',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None,
            access_tier='Hot'
        )

        all_rules = rules.check_all_rules(azure_blob)

        # Should have violations
        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'non_compliant'
        assert encryption_rule.status.value == 'non_compliant'

    def test_compliance_rules_non_compliant_gcp(self):
        """Test non-compliant GCP bucket."""
        rules = GDPRRules()

        # Test non-compliant GCP bucket
        gcp_bucket = GCPBucketDetails(
            name='non-compliant-bucket',
            project_id='test-project',
            location='US-CENTRAL1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None,
            storage_class='STANDARD',
            versioning_enabled=False,
            uniform_bucket_level_access=False
        )

        all_rules = rules.check_all_rules(gcp_bucket)

        # Should have violations
        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'non_compliant'
        assert encryption_rule.status.value == 'non_compliant'


class TestComplianceRules:
    """Test cases for GDPR compliance rules."""

    def test_gdpr_rules_initialization(self):
        """Test GDPR rules engine initializes correctly."""
        rules = GDPRRules()
        assert len(rules.rules) == 3
        assert 'GDPR-STORAGE-001' in rules.rules

    def test_check_s3_public_access_compliant(self):
        """Test public access check for compliant bucket."""
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        rule = rules.check_storage_public_access(bucket_details)

        assert rule.rule_id == 'GDPR-STORAGE-001'
        assert rule.status.value == 'compliant'

    def test_check_s3_public_access_non_compliant(self):
        """Test public access check for non-compliant bucket."""
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        rule = rules.check_storage_public_access(bucket_details)

        assert rule.rule_id == 'GDPR-STORAGE-001'
        assert rule.status.value == 'non_compliant'
        assert 'public access' in rule.details.lower()

    def test_check_all_rules(self):
        """Test checking all GDPR rules."""
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        all_rules = rules.check_all_rules(bucket_details)

        assert len(all_rules) == 3
        rule_ids = [rule.rule_id for rule in all_rules]
        assert 'GDPR-STORAGE-001' in rule_ids
        assert 'GDPR-STORAGE-002' in rule_ids
        assert 'GDPR-STORAGE-003' in rule_ids


class TestRiskAssessor:
    """Test cases for risk assessment."""

    def test_risk_assessor_initialization(self):
        """Test risk assessor initializes correctly."""
        assessor = RiskAssessor()
        assert len(assessor.risk_weights) > 0

    def test_calculate_risk_score_compliant(self):
        """Test risk calculation for compliant resources."""
        assessor = RiskAssessor()
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        rules_checked = rules.check_all_rules(bucket_details)
        risk_score, risk_level = assessor.calculate_risk_score(rules_checked, bucket_details)

        assert risk_score >= 0
        assert risk_score <= 100
        assert risk_level.value in ['low', 'medium', 'high', 'critical']

    def test_calculate_risk_score_non_compliant(self):
        """Test risk calculation for non-compliant resources."""
        assessor = RiskAssessor()
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None
        )

        rules_checked = rules.check_all_rules(bucket_details)
        risk_score, risk_level = assessor.calculate_risk_score(rules_checked, bucket_details)

        # Should have high risk due to public access and no encryption
        assert risk_score > 50
        assert risk_level.value in ['high', 'critical']

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        assessor = RiskAssessor()
        rules = GDPRRules()

        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None
        )

        rules_checked = rules.check_all_rules(bucket_details)
        recommendations = assessor.generate_recommendations(rules_checked, bucket_details)

        assert len(recommendations) > 0
        assert any('public access' in rec.lower() for rec in recommendations)
        assert any('encryption' in rec.lower() for rec in recommendations)
