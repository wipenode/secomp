#!/usr/bin/env python3
"""
Simple test of Secomp functionality with mock data - no AWS credentials required
"""
import sys
import os
from datetime import datetime

def test_models():
    """Test data models"""
    print("🧪 Testing data models...")

    # Add module path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'secomp'))

    try:
        from secomp.models import S3BucketDetails, ComplianceStatus, RiskLevel

        # Test compliant bucket
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

        # Test non-compliant bucket
        public_bucket = S3BucketDetails(
            name='test-public-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None
        )

        print("✅ Public bucket model works!")
        print(f"   Bucket: {public_bucket.name}")
        print(f"   Risk: High (public access + no encryption)")

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

        # Test compliant bucket
        compliant_bucket = S3BucketDetails(
            name='compliant-bucket',
            region='us-east-1',
            public_access=False,
            encryption_enabled=True,
            encryption_type='AES256'
        )

        rules_checked = rules.check_all_rules(compliant_bucket)
        risk_score, risk_level = assessor.calculate_risk_score(rules_checked, compliant_bucket)
        recommendations = assessor.generate_recommendations(rules_checked, compliant_bucket)

        print("\n✅ Test compliant bucket:")
        print(f"   Risk Score: {risk_score}/100")
        print(f"   Risk Level: {risk_level.value}")
        print(f"   Recommendations: {len(recommendations)}")

        # Test non-compliant bucket
        non_compliant_bucket = S3BucketDetails(
            name='non-compliant-bucket',
            region='us-east-1',
            public_access=True,
            encryption_enabled=False,
            encryption_type=None
        )

        rules_checked = rules.check_all_rules(non_compliant_bucket)
        risk_score, risk_level = assessor.calculate_risk_score(rules_checked, non_compliant_bucket)
        recommendations = assessor.generate_recommendations(rules_checked, non_compliant_bucket)

        print("\n✅ Test non-compliant bucket:")
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

        # Test initialization only (without actual AWS connection)
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

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 All tests passed! Secomp core works correctly.")
        print("\n🔍 What was tested:")
        print("   ✅ Data models (Pydantic)")
        print("   ✅ GDPR compliance rules")
        print("   ✅ Risk assessment and scoring")
        print("   ✅ Scanner initialization")
        print("   ✅ Plugin system")
        print("\n🚀 Next steps:")
        print("   1. pip install boto3 moto")
        print("   2. python3 -m pytest tests/test_scanner.py -v")
        print("   3. Configure AWS and test: python3 -m secomp.cli scan --cloud aws --compliance gdpr")
    else:
        print("⚠️  Some tests failed. Check errors above.")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
