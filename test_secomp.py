#!/usr/bin/env python3
"""
Simple test script for Secomp core functionality.
Run this after installing dependencies: pip install -r requirements.txt
"""
import sys
import os
from datetime import datetime, timezone

# Add the secomp module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'secomp', 'secomp'))

def test_models():
    """Test the data models."""
    try:
        from models import ComplianceReport, ResourceFinding, ComplianceStatus, RiskLevel, S3BucketDetails

        # Create test data
        bucket_details = S3BucketDetails(
            name='test-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        finding = ResourceFinding(
            resource_id='test-bucket',
            resource_type='s3_bucket',
            resource_details=bucket_details.dict(),
            compliance_status=ComplianceStatus.COMPLIANT,
            risk_score=0,
            risk_level=RiskLevel.LOW,
            rules_checked=[],
            recommendations=[],
            timestamp=datetime.now(timezone.utc)
        )

        report = ComplianceReport(
            scan_id='test-scan-123',
            cloud_provider='aws',
            compliance_framework='gdpr',
            total_resources=1,
            compliant_resources=1,
            non_compliant_resources=0,
            overall_risk_score=0,
            findings=[finding]
        )

        print("✅ Models test passed!")
        print(f"   Report: {report.scan_id}")
        print(f"   Overall Risk: {report.overall_risk_score}/100")
        return True

    except Exception as e:
        print(f"❌ Models test failed: {e}")
        return False

def test_compliance_rules():
    """Test the compliance rules engine."""
    try:
        from compliance import GDPRRules, RiskAssessor
        from models import S3BucketDetails

        rules = GDPRRules()
        assessor = RiskAssessor()

        # Test compliant bucket
        bucket_details = S3BucketDetails(
            name='compliant-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        rules_checked = rules.check_all_rules(bucket_details)
        risk_score, risk_level = assessor.calculate_risk_score(rules_checked, bucket_details)

        print("✅ Compliance rules test passed!")
        print(f"   Rules checked: {len(rules_checked)}")
        print(f"   Risk Score: {risk_score}/100")
        print(f"   Risk Level: {risk_level.value}")
        return True

    except Exception as e:
        print(f"❌ Compliance rules test failed: {e}")
        return False

def test_scanner_mock():
    """Test the scanner with mocked data."""
    try:
        # This would require moto for full testing
        from scanner import AWSScanner
        from models import S3BucketDetails

        # Test scanner initialization (without AWS credentials)
        scanner = AWSScanner(region='us-east-1', debug=True)

        print("✅ Scanner initialization test passed!")
        print(f"   Region: {scanner.region}")
        print(f"   Debug mode: {scanner.debug}")
        return True

    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        return False

def test_cli_help():
    """Test CLI help functionality."""
    try:
        from cli import cli
        import click.testing

        runner = click.testing.CliRunner()
        result = runner.invoke(cli, ['--help'])

        if result.exit_code == 0 and 'secomp' in result.output.lower():
            print("✅ CLI help test passed!")
            print("   Help output available")
            return True
        else:
            print(f"❌ CLI help test failed: {result.output}")
            return False

    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Testing Secomp Core Functionality")
    print("=" * 40)

    tests = [
        test_models,
        test_compliance_rules,
        test_scanner_mock,
        test_cli_help
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        print(f"\n🔍 Running {test.__name__}...")
        if test():
            passed += 1

    print("\n" + "=" * 40)
    print(f"📊 Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 All tests passed! Secomp is ready to use.")
        print("\n🚀 Next steps:")
        print("   1. Configure AWS credentials: aws configure")
        print("   2. Run scan: python3 -m secomp.cli scan --cloud aws --compliance gdpr")
        print("   3. Run full tests: python3 -m pytest tests/ -v")
    else:
        print("⚠️  Some tests failed. Check dependencies and installation.")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
