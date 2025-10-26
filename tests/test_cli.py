"""
Unit tests for CLI functionality.
"""
import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from secomp.cli import cli, scan
from secomp.models import ComplianceReport, ResourceFinding, ComplianceStatus, RiskLevel
from secomp.scanner import AWSScanner, AzureScanner, GCPScanner


class TestCLI:
    """Test cases for CLI commands."""

    def test_cli_version(self):
        """Test CLI version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert '0.1.0' in result.output
    def test_scan_command_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(scan, ['--help'])
        assert result.exit_code == 0
        assert '--cloud' in result.output
        assert '--compliance' in result.output
        assert '--output' in result.output

    @patch('secomp.cli.create_azure_scanner')
    def test_scan_command_azure_success(self, mock_create_azure_scanner):
        """Test successful Azure scan."""
        # Mock scanner and findings
        mock_scanner = MagicMock()
        mock_findings = [
            ResourceFinding(
                resource_id='test-rg/test-container-1',
                resource_type='azure_blob_container',
                resource_details={'name': 'test-container-1', 'resource_group': 'test-rg'},
                compliance_status=ComplianceStatus.COMPLIANT,
                risk_score=0,
                risk_level=RiskLevel.LOW,
                rules_checked=[],
                recommendations=[],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]
        mock_scanner.scan_blob_containers.return_value = mock_findings
        mock_create_azure_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'azure',
            '--compliance', 'gdpr',
            '--region', 'test-rg',
            '--format', 'table'
        ])

        assert result.exit_code == 0
        assert 'Secomp Compliance Report' in result.output
        assert 'Azure' in result.output

    @patch('secomp.cli.create_gcp_scanner')
    def test_scan_command_gcp_success(self, mock_create_gcp_scanner):
        """Test successful GCP scan."""
        # Mock scanner and findings
        mock_scanner = MagicMock()
        mock_findings = [
            ResourceFinding(
                resource_id='test-project/test-bucket-1',
                resource_type='gcp_storage_bucket',
                resource_details={'name': 'test-bucket-1', 'project_id': 'test-project'},
                compliance_status=ComplianceStatus.COMPLIANT,
                risk_score=0,
                risk_level=RiskLevel.LOW,
                rules_checked=[],
                recommendations=[],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]
        mock_scanner.scan_storage_buckets.return_value = mock_findings
        mock_create_gcp_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'gcp',
            '--compliance', 'gdpr',
            '--region', 'test-project',
            '--format', 'table'
        ])

        assert result.exit_code == 0
        assert 'Secomp Compliance Report' in result.output
        assert 'GCP' in result.output

    def test_scan_command_missing_cloud(self):
        """Test scan command without required cloud parameter."""
        runner = CliRunner()
        result = runner.invoke(scan, ['--compliance', 'gdpr'])
        assert result.exit_code != 0
        assert 'Missing option' in result.output or 'Error' in result.output

    def test_scan_command_missing_compliance(self):
        """Test scan command without required compliance parameter."""
        runner = CliRunner()
        result = runner.invoke(scan, ['--cloud', 'aws'])
        assert result.exit_code != 0
        assert 'Missing option' in result.output or 'Error' in result.output

    @patch('secomp.cli.create_scanner')
    def test_scan_command_aws_success(self, mock_create_scanner):
        """Test successful AWS scan."""
        # Mock scanner and findings
        mock_scanner = MagicMock()
        mock_findings = [
            ResourceFinding(
                resource_id='test-bucket-1',
                resource_type='s3_bucket',
                resource_details={'name': 'test-bucket-1', 'region': 'us-east-1'},
                compliance_status=ComplianceStatus.COMPLIANT,
                risk_score=0,
                risk_level=RiskLevel.LOW,
                rules_checked=[],
                recommendations=[],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]
        mock_scanner.scan_s3_buckets.return_value = mock_findings
        mock_create_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'aws',
            '--compliance', 'gdpr',
            '--region', 'us-east-1',
            '--format', 'table'
        ])

        assert result.exit_code == 0
        assert 'Secomp Compliance Report' in result.output
        assert 'test-bucket-1' in result.output

    @patch('secomp.cli.create_scanner')
    def test_scan_command_aws_with_output_file(self, mock_create_scanner):
        """Test AWS scan with output file."""
        # Mock scanner and findings
        mock_scanner = MagicMock()
        mock_findings = [
            ResourceFinding(
                resource_id='test-bucket-1',
                resource_type='s3_bucket',
                resource_details={'name': 'test-bucket-1', 'region': 'us-east-1'},
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                risk_score=50,
                risk_level=RiskLevel.MEDIUM,
                rules_checked=[],
                recommendations=['Fix public access'],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]
        mock_scanner.scan_s3_buckets.return_value = mock_findings
        mock_create_scanner.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'aws',
            '--compliance', 'gdpr',
            '--region', 'us-east-1',
            '--output', 'test-report.json'
        ])

        assert result.exit_code == 0
        assert 'Report saved to test-report.json' in result.output

        # Check if file was created
        import os
        assert os.path.exists('test-report.json')

        # Clean up
        if os.path.exists('test-report.json'):
            os.remove('test-report.json')

    @patch('secomp.cli.create_scanner')
    def test_scan_command_unsupported_cloud(self, mock_create_scanner):
        """Test scan with unsupported cloud provider."""
        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'azure',
            '--compliance', 'gdpr'
        ])

        assert result.exit_code == 0  # Should not exit with error, just warn
        assert 'not yet supported' in result.output.lower()

    def test_scan_command_debug_mode(self):
        """Test scan command in debug mode."""
        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'aws',
            '--compliance', 'gdpr',
            '--debug'
        ])

        # Should fail due to no AWS credentials, but debug info should be shown
        assert result.exit_code != 0
        assert 'Debug Mode' in result.output or 'Error' in result.output

    def test_plugins_command(self):
        """Test plugins command."""
        runner = CliRunner()
        result = runner.invoke(cli, ['plugins'])
        assert result.exit_code == 0
        assert 'Plugin System' in result.output
        assert 'AWS S3 Scanner' in result.output


class TestComplianceReport:
    """Test cases for compliance report generation."""

    def test_report_creation(self):
        """Test creating a compliance report."""
        findings = [
            ResourceFinding(
                resource_id='test-bucket-1',
                resource_type='s3_bucket',
                resource_details={'name': 'test-bucket-1', 'region': 'us-east-1'},
                compliance_status=ComplianceStatus.COMPLIANT,
                risk_score=0,
                risk_level=RiskLevel.LOW,
                rules_checked=[],
                recommendations=[],
                timestamp=__import__('datetime').datetime.utcnow()
            ),
            ResourceFinding(
                resource_id='test-bucket-2',
                resource_type='s3_bucket',
                resource_details={'name': 'test-bucket-2', 'region': 'us-east-1'},
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                risk_score=80,
                risk_level=RiskLevel.HIGH,
                rules_checked=[],
                recommendations=['Fix encryption'],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]

        report = ComplianceReport(
            scan_id='test-scan-123',
            cloud_provider='aws',
            compliance_framework='gdpr',
            total_resources=2,
            compliant_resources=1,
            non_compliant_resources=1,
            overall_risk_score=40,  # Average of 0 and 80
            findings=findings
        )

        assert report.scan_id == 'test-scan-123'
        assert report.cloud_provider == 'aws'
        assert report.compliance_framework == 'gdpr'
        assert report.total_resources == 2
        assert report.compliant_resources == 1
        assert report.non_compliant_resources == 1
        assert report.overall_risk_score == 40
        assert len(report.findings) == 2

    def test_report_json_serialization(self):
        """Test JSON serialization of report."""
        findings = [
            ResourceFinding(
                resource_id='test-bucket-1',
                resource_type='s3_bucket',
                resource_details={'name': 'test-bucket-1'},
                compliance_status=ComplianceStatus.COMPLIANT,
                risk_score=0,
                risk_level=RiskLevel.LOW,
                rules_checked=[],
                recommendations=[],
                timestamp=__import__('datetime').datetime.utcnow()
            )
        ]

        report = ComplianceReport(
            scan_id='test-scan-123',
            cloud_provider='aws',
            compliance_framework='gdpr',
            total_resources=1,
            compliant_resources=1,
            non_compliant_resources=0,
            overall_risk_score=0,
            findings=findings
        )

        # Test JSON serialization
        json_str = report.json()
        assert isinstance(json_str, str)

        # Test JSON deserialization
        json_data = report.dict()
        assert json_data['scan_id'] == 'test-scan-123'
        assert json_data['cloud_provider'] == 'aws'
        assert len(json_data['findings']) == 1
