"""
Unit tests for CLI functionality.
"""
import os
import json
from datetime import datetime, timezone
from click.testing import CliRunner
from unittest.mock import patch, MagicMock

from secomp.cli import cli, scan
from secomp.models import ComplianceReport, ResourceFinding, ComplianceStatus, RiskLevel


def _make_finding(resource_id: str, resource_type: str, compliant: bool = True) -> ResourceFinding:
    return ResourceFinding(
        resource_id=resource_id,
        resource_type=resource_type,
        resource_details={'name': resource_id},
        compliance_status=ComplianceStatus.COMPLIANT if compliant else ComplianceStatus.NON_COMPLIANT,
        risk_score=0 if compliant else 50,
        risk_level=RiskLevel.LOW if compliant else RiskLevel.MEDIUM,
        rules_checked=[],
        recommendations=[] if compliant else ['Fix public access'],
        timestamp=datetime.now(timezone.utc)
    )


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
        mock_scanner = MagicMock()
        mock_scanner.scan_blob_containers.return_value = [
            _make_finding('test-rg/test-container-1', 'azure_blob_container')
        ]
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
        assert 'AZURE' in result.output

    @patch('secomp.cli.create_gcp_scanner')
    def test_scan_command_gcp_success(self, mock_create_gcp_scanner):
        """Test successful GCP scan."""
        mock_scanner = MagicMock()
        mock_scanner.scan_storage_buckets.return_value = [
            _make_finding('test-project/test-bucket-1', 'gcp_storage_bucket')
        ]
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

    def test_scan_command_unimplemented_framework(self):
        """Frameworks accepted by the CLI but not implemented should fail clearly."""
        runner = CliRunner()
        result = runner.invoke(scan, [
            '--cloud', 'aws',
            '--compliance', 'nis2',
        ])
        assert result.exit_code == 2
        assert 'not implemented' in result.output.lower()

    @patch('secomp.cli.create_scanner')
    def test_scan_command_aws_success(self, mock_create_scanner):
        """Test successful AWS scan."""
        mock_scanner = MagicMock()
        mock_scanner.scan_s3_buckets.return_value = [
            _make_finding('test-bucket-1', 's3_bucket')
        ]
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
        mock_scanner = MagicMock()
        mock_scanner.scan_s3_buckets.return_value = [
            _make_finding('test-bucket-1', 's3_bucket', compliant=False)
        ]
        mock_create_scanner.return_value = mock_scanner

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(scan, [
                '--cloud', 'aws',
                '--compliance', 'gdpr',
                '--region', 'us-east-1',
                '--output', 'test-report.json'
            ])

            assert result.exit_code == 0
            assert 'Report saved to test-report.json' in result.output
            assert os.path.exists('test-report.json')

            with open('test-report.json', encoding='utf-8') as f:
                data = json.load(f)
            assert data['cloud_provider'] == 'aws'
            assert data['total_resources'] == 1

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
            _make_finding('test-bucket-1', 's3_bucket', compliant=True),
            _make_finding('test-bucket-2', 's3_bucket', compliant=False),
        ]

        report = ComplianceReport(
            scan_id='test-scan-123',
            cloud_provider='aws',
            compliance_framework='gdpr',
            total_resources=2,
            compliant_resources=1,
            non_compliant_resources=1,
            overall_risk_score=25,
            findings=findings
        )

        assert report.scan_id == 'test-scan-123'
        assert report.cloud_provider == 'aws'
        assert report.compliance_framework == 'gdpr'
        assert report.total_resources == 2
        assert report.compliant_resources == 1
        assert report.non_compliant_resources == 1
        assert len(report.findings) == 2

    def test_report_json_serialization(self):
        """Test JSON serialization of report."""
        report = ComplianceReport(
            scan_id='test-scan-123',
            cloud_provider='aws',
            compliance_framework='gdpr',
            total_resources=1,
            compliant_resources=1,
            non_compliant_resources=0,
            overall_risk_score=0,
            findings=[_make_finding('test-bucket-1', 's3_bucket')]
        )

        json_str = report.model_dump_json()
        assert isinstance(json_str, str)

        json_data = report.model_dump()
        assert json_data['scan_id'] == 'test-scan-123'
        assert json_data['cloud_provider'] == 'aws'
        assert len(json_data['findings']) == 1
