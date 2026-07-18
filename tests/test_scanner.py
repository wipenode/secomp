"""
Unit tests for scanner functionality using moto for AWS mocking.
"""
import os

import pytest
import boto3
from moto import mock_aws

from secomp.scanner import AWSScanner, AzureScanner, GCPScanner
from secomp.models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails
from secomp.compliance import GDPRRules, RiskAssessor


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Fake AWS credentials so tests never touch a real account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def mock_s3_client():
    """Create a mock S3 client."""
    with mock_aws():
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
        mock_s3_client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')

        details = scanner.get_bucket_details(bucket_name)

        assert details.name == bucket_name
        assert details.public_access is True
        assert details.encryption_enabled is False

    def test_get_bucket_details_encrypted_bucket(self, scanner, mock_s3_client):
        """Test getting details of an encrypted bucket."""
        bucket_name = 'encrypted-test-bucket'
        mock_s3_client.create_bucket(Bucket=bucket_name)

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
        public_bucket = 'public-bucket'
        private_bucket = 'private-bucket'

        mock_s3_client.create_bucket(Bucket=public_bucket)
        mock_s3_client.create_bucket(Bucket=private_bucket)

        mock_s3_client.put_bucket_acl(Bucket=public_bucket, ACL='public-read')

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

        public_finding = next(f for f in findings if f.resource_id == public_bucket)
        assert public_finding.compliance_status.value == 'non_compliant'
        assert public_finding.risk_score > 0
        assert len(public_finding.recommendations) > 0

        private_finding = next(f for f in findings if f.resource_id == private_bucket)
        assert private_finding.compliance_status.value == 'compliant'


class TestAzureScanner:
    """Test cases for Azure Blob Storage scanner (without credentials)."""

    def test_azure_scanner_initialization(self, monkeypatch):
        """Test Azure scanner initializes correctly without credentials."""
        monkeypatch.delenv('AZURE_STORAGE_ACCOUNT_URL', raising=False)
        monkeypatch.delenv('AZURE_STORAGE_CONNECTION_STRING', raising=False)

        scanner = AzureScanner(resource_group='test-rg', debug=False)
        assert scanner.resource_group == 'test-rg'
        assert scanner.debug is False
        assert scanner.blob_client is None

    def test_azure_list_containers_without_client(self, monkeypatch):
        """Without credentials, listing returns an empty list instead of fake data."""
        monkeypatch.delenv('AZURE_STORAGE_ACCOUNT_URL', raising=False)
        monkeypatch.delenv('AZURE_STORAGE_CONNECTION_STRING', raising=False)

        scanner = AzureScanner(resource_group='test-rg')
        assert scanner.list_blob_containers() == []

    def test_azure_get_container_details_without_client(self, monkeypatch):
        """Without credentials, details raise instead of fabricating compliant data."""
        monkeypatch.delenv('AZURE_STORAGE_ACCOUNT_URL', raising=False)
        monkeypatch.delenv('AZURE_STORAGE_CONNECTION_STRING', raising=False)

        scanner = AzureScanner(resource_group='test-rg')
        with pytest.raises(RuntimeError):
            scanner.get_container_details('test-container-1')

    def test_azure_scan_without_client(self, monkeypatch):
        """Without credentials, scan returns no findings."""
        monkeypatch.delenv('AZURE_STORAGE_ACCOUNT_URL', raising=False)
        monkeypatch.delenv('AZURE_STORAGE_CONNECTION_STRING', raising=False)

        scanner = AzureScanner(resource_group='test-rg')
        assert scanner.scan_blob_containers() == []


class TestGCPScanner:
    """Test cases for GCP Cloud Storage scanner (without credentials)."""

    @pytest.fixture(autouse=True)
    def no_gcp_credentials(self, monkeypatch):
        monkeypatch.delenv('GOOGLE_APPLICATION_CREDENTIALS', raising=False)

    def test_gcp_scanner_initialization(self):
        """Test GCP scanner initializes correctly."""
        scanner = GCPScanner(project_id='test-project', debug=False)
        assert scanner.project_id == 'test-project'
        assert scanner.debug is False

    def test_gcp_list_buckets_without_client(self):
        """Without credentials, listing returns an empty list instead of fake data."""
        scanner = GCPScanner(project_id='test-project')
        if scanner.storage_client is not None:
            pytest.skip("Real GCP credentials available in environment")
        assert scanner.list_storage_buckets() == []

    def test_gcp_get_bucket_details_without_client(self):
        """Without credentials, details raise instead of fabricating compliant data."""
        scanner = GCPScanner(project_id='test-project')
        if scanner.storage_client is not None:
            pytest.skip("Real GCP credentials available in environment")
        with pytest.raises(RuntimeError):
            scanner.get_bucket_details('test-bucket-1')

    def test_gcp_scan_without_client(self):
        """Without credentials, scan returns no findings."""
        scanner = GCPScanner(project_id='test-project')
        if scanner.storage_client is not None:
            pytest.skip("Real GCP credentials available in environment")
        assert scanner.scan_storage_buckets() == []


class TestMultiCloudCompliance:
    """Test compliance rules across multiple cloud providers."""

    def test_compliance_rules_azure_blob(self):
        """Test GDPR compliance rules for Azure Blob."""
        rules = GDPRRules()

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

        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'compliant'
        assert encryption_rule.status.value == 'compliant'

    def test_compliance_rules_gcp_bucket(self):
        """Test GDPR compliance rules for GCP Storage."""
        rules = GDPRRules()

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

        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'compliant'
        assert encryption_rule.status.value == 'compliant'

    def test_compliance_rules_non_compliant_azure(self):
        """Test non-compliant Azure blob."""
        rules = GDPRRules()

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

        public_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-001')
        encryption_rule = next(r for r in all_rules if r.rule_id == 'GDPR-STORAGE-002')
        assert public_rule.status.value == 'non_compliant'
        assert encryption_rule.status.value == 'non_compliant'

    def test_compliance_rules_non_compliant_gcp(self):
        """Test non-compliant GCP bucket."""
        rules = GDPRRules()

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

        assert 0 <= risk_score <= 100
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
