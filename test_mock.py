#!/usr/bin/env python3
"""
Simple smoke test of Secomp functionality with mock data - no cloud credentials required.

Run from the repository root: python test_mock.py
For the full test suite use: pytest tests/ -v
"""
import sys

# Legacy Windows consoles default to cp1252 and crash on emoji output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def test_models():
    """Test data models"""
    print("🧪 Testing data models...")

    try:
        from secomp.models import S3BucketDetails

        bucket = S3BucketDetails(
            name='test-compliant-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        print("✅ S3BucketDetails model works!")
        print(f"   Bucket: {bucket.name}")
        print(f"   Region: {bucket.region}")
        print(f"   Public Access: {bucket.public_access}")
        print(f"   Encryption: {bucket.encryption_enabled} ({bucket.encryption_type})")

        public_bucket = S3BucketDetails(
            name='test-public-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None
        )

        print("✅ Public bucket model works!")
        print(f"   Bucket: {public_bucket.name}")
        print("   Risk: High (public access + no encryption)")

        return True

    except Exception as e:
        print(f"❌ Error in models: {e}")
        return False


def test_compliance_rules():
    """Test compliance rules"""
    print("\n🧪 Testing compliance rules...")

    try:
        from secomp.compliance import GDPRRules, RiskAssessor
        from secomp.models import S3BucketDetails

        rules = GDPRRules()
        assessor = RiskAssessor()

        print("✅ GDPR Rules engine works!")
        print(f"   Available rules: {len(rules.rules)}")
        for rule_id, rule_info in rules.rules.items():
            print(f"   - {rule_id}: {rule_info['name']}")

        for label, bucket in [
            ("compliant", S3BucketDetails(
                name='compliant-bucket', region='us-east-1',
                public_access=False, encryption_enabled=True, encryption_type='AES256')),
            ("non-compliant", S3BucketDetails(
                name='non-compliant-bucket', region='us-east-1',
                public_access=True, encryption_enabled=False, encryption_type=None)),
        ]:
            rules_checked = rules.check_all_rules(bucket)
            risk_score, risk_level = assessor.calculate_risk_score(rules_checked, bucket)
            recommendations = assessor.generate_recommendations(rules_checked, bucket)

            print(f"\n✅ Test {label} bucket:")
            print(f"   Risk Score: {risk_score}/100")
            print(f"   Risk Level: {risk_level.value}")
            print(f"   Recommendations: {len(recommendations)}")

        return True

    except Exception as e:
        print(f"❌ Error in compliance: {e}")
        return False


def test_scanner_initialization():
    """Test scanner initialization (without AWS)"""
    print("\n🧪 Testing scanner initialization...")

    try:
        from secomp.scanner import AWSScanner

        scanner = AWSScanner(region='us-east-1', debug=True)

        print("✅ Scanner initialization works!")
        print(f"   Region: {scanner.region}")
        print(f"   Debug mode: {scanner.debug}")

        return True

    except Exception as e:
        print(f"❌ Error in scanner: {e}")
        return False


def test_plugin_system():
    """Test plugin system"""
    print("\n🧪 Testing plugin system...")

    try:
        from secomp.plugins import PluginManager

        manager = PluginManager()

        print("✅ Plugin system works!")
        print(f"   Cloud plugins: {manager.list_cloud_plugins()}")
        print(f"   Compliance plugins: {manager.list_compliance_plugins()}")

        return True

    except Exception as e:
        print(f"❌ Error in plugin system: {e}")
        return False


def main():
    """Run all tests"""
    print("🚀 Secomp Mock Data Tests")
    print("=" * 50)

    tests = [
        test_models,
        test_compliance_rules,
        test_scanner_initialization,
        test_plugin_system
    ]

    passed = sum(1 for test in tests if test())
    total = len(tests)

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 All tests passed! Secomp core works correctly.")
        print("\n🚀 Next steps:")
        print("   1. pip install -e .[test]")
        print("   2. pytest tests/ -v")
        print("   3. Configure AWS and test: secomp scan --cloud aws --compliance gdpr")
    else:
        print("⚠️  Some tests failed. Check errors above.")

    return passed == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
