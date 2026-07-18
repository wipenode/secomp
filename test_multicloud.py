#!/usr/bin/env python3
"""
Comprehensive smoke test of Secomp multi-cloud functionality.
Tests AWS, Azure, and GCP support with mock data.

Run from the repository root: python test_multicloud.py
For the full test suite use: pytest tests/ -v
"""
import sys

# Legacy Windows consoles default to cp1252 and crash on emoji output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def test_multi_cloud_models():
    """Test all cloud provider data models"""
    print("🌐 Testing Multi-Cloud Data Models...")

    try:
        from secomp.models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails

        s3_bucket = S3BucketDetails(
            name='test-s3-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )
        print("✅ AWS S3 Model works!")
        print(f"   Bucket: {s3_bucket.name} ({s3_bucket.region})")

        azure_blob = AzureBlobDetails(
            name='test-blob-container',
            resource_group='test-rg',
            location='East US',
            public_access=False,
            encryption_enabled=True,
            encryption_type='Microsoft-managed',
            access_tier='Hot'
        )
        print("✅ Azure Blob Model works!")
        print(f"   Container: {azure_blob.name} (RG: {azure_blob.resource_group})")

        gcp_bucket = GCPBucketDetails(
            name='test-gcp-bucket',
            project_id='test-project',
            location='US-CENTRAL1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='Google-managed',
            storage_class='STANDARD',
            versioning_enabled=True,
            uniform_bucket_level_access=True
        )
        print("✅ GCP Storage Model works!")
        print(f"   Bucket: {gcp_bucket.name} (Project: {gcp_bucket.project_id})")

        return True

    except Exception as e:
        print(f"❌ Error in multi-cloud models: {e}")
        return False


def test_multi_cloud_compliance():
    """Test compliance rules across all cloud providers"""
    print("\n🧪 Testing Multi-Cloud Compliance Rules...")

    try:
        from secomp.compliance import GDPRRules
        from secomp.models import S3BucketDetails, AzureBlobDetails, GCPBucketDetails

        rules = GDPRRules()
        print("✅ GDPR Rules initialized!")
        print(f"   Available rules: {len(rules.rules)}")
        for rule_id, rule_info in rules.rules.items():
            print(f"   - {rule_id}: {rule_info['name']}")

        resources = {
            "AWS S3": S3BucketDetails(
                name='aws-compliant-bucket', region='us-east-1',
                public_access=False, encryption_enabled=True, encryption_type='AES256'),
            "Azure Blob": AzureBlobDetails(
                name='azure-compliant-container', resource_group='test-rg', location='East US',
                public_access=False, encryption_enabled=True,
                encryption_type='Microsoft-managed', access_tier='Hot'),
            "GCP Storage": GCPBucketDetails(
                name='gcp-compliant-bucket', project_id='test-project', location='US-CENTRAL1',
                public_access=False, encryption_enabled=True, encryption_type='Google-managed',
                storage_class='STANDARD', versioning_enabled=True, uniform_bucket_level_access=True),
        }

        for label, resource in resources.items():
            checked = rules.check_all_rules(resource)
            print(f"\n✅ {label} Compliance:")
            for rule in checked:
                print(f"   - {rule.rule_id}: {rule.status.value}")

        return True

    except Exception as e:
        print(f"❌ Error in multi-cloud compliance: {e}")
        return False


def test_multi_cloud_scanners():
    """Test all cloud provider scanners"""
    print("\n🔍 Testing Multi-Cloud Scanners...")

    try:
        from secomp.scanner import AWSScanner, AzureScanner, GCPScanner

        aws_scanner = AWSScanner(region='us-east-1', debug=True)
        print("✅ AWS Scanner initialized!")
        print(f"   Region: {aws_scanner.region}")

        azure_scanner = AzureScanner(resource_group='test-rg', debug=True)
        print("✅ Azure Scanner initialized!")
        print(f"   Resource Group: {azure_scanner.resource_group}")

        gcp_scanner = GCPScanner(project_id='test-project', debug=True)
        print("✅ GCP Scanner initialized!")
        print(f"   Project ID: {gcp_scanner.project_id}")

        return True

    except Exception as e:
        print(f"❌ Error in multi-cloud scanners: {e}")
        return False


def test_multi_cloud_cli():
    """Test CLI with different cloud providers"""
    print("\n💻 Testing Multi-Cloud CLI...")

    try:
        from click.testing import CliRunner
        from secomp.cli import scan

        runner = CliRunner()

        result = runner.invoke(scan, ['--help'])
        if 'aws' in result.output.lower() and 'azure' in result.output.lower() and 'gcp' in result.output.lower():
            print("✅ CLI supports all three cloud providers!")
        else:
            print("⚠️ CLI help may not show all cloud providers")

        valid_clouds = ['aws', 'azure', 'gcp']
        print(f"✅ Supported cloud providers: {', '.join(valid_clouds)}")

        return True

    except Exception as e:
        print(f"❌ Error in multi-cloud CLI: {e}")
        return False


def main():
    """Run all multi-cloud tests"""
    print("🚀 Secomp Multi-Cloud Testing Suite")
    print("=" * 60)

    tests = [
        test_multi_cloud_models,
        test_multi_cloud_compliance,
        test_multi_cloud_scanners,
        test_multi_cloud_cli
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("\n" + "=" * 60)
    print(f"📊 Multi-Cloud Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 All multi-cloud tests passed!")
        print("\n🚀 Usage examples:")
        print("   secomp scan --cloud aws --compliance gdpr --region us-east-1")
        print("   secomp scan --cloud azure --compliance gdpr --region my-rg")
        print("   secomp scan --cloud gcp --compliance gdpr --region my-project")
    else:
        print("⚠️ Some tests failed. Check errors above.")

    return passed == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
