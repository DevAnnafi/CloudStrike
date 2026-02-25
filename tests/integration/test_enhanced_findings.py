import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.aws.s3_checker import S3Scanner
from scanners.azure.storage_checker import StorageChecker
from scanners.gcp.bucket_checker import BucketScanner
from unittest.mock import patch, MagicMock

print("Testing Enhanced Finding Fields...")
print("=" * 60)

print("\n[AWS] Testing S3Scanner with account_name...")
aws_scanner = S3Scanner(account_name="Test AWS Account")
print(f"✓ Account Name: {aws_scanner.account_name}")
print(f"✓ Account ID: {aws_scanner.account_id}")

print("\n[Azure] Testing StorageChecker with account_name...")
azure_scanner = StorageChecker(subscription_id="test-sub-123", account_name="Test Azure Sub")
print(f"Account Name: {azure_scanner.account_name}")
print(f"Subscription ID: {azure_scanner.subscription_id}")

print("\n[GCP] Testing BucketScanner with account_name...")
gcp_scanner = BucketScanner(project_id="test-project-123", account_name="Test GCP Project")
print(f"✓ Account Name: {gcp_scanner.account_name}")
print(f"✓ Project ID: {gcp_scanner.project_id}")

print("\n" + "=" * 60)
print("All scanners support enhanced fields!")

print("Testing Enhanced Finding Structure...")
print("=" * 60)

with patch('scanners.aws.s3_checker.boto3.Session') as mock_session:
    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.side_effect = Exception("Not configured")
    
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    
    mock_session.return_value.client.side_effect = lambda service: mock_sts if service == 'sts' else mock_s3
    
    scanner = S3Scanner(account_name="Production AWS")
    scanner.check_public_access("test-bucket")
    
    if scanner.findings:
        finding = scanner.findings[0]
        print("\n✓ Finding created with enhanced fields:")
        print(f"  Severity: {finding['severity']}")
        print(f"  Title: {finding['title']}")
        print(f"  Resource: {finding['resource']}")
        print(f"  Cloud Provider: {finding.get('cloud_provider', 'MISSING!')}")
        print(f"  Account ID: {finding.get('account_id', 'MISSING!')}")
        print(f"  Account Name: {finding.get('account_name', 'MISSING!')}")
        
        assert 'cloud_provider' in finding
        assert 'account_id' in finding
        assert 'account_name' in finding
        assert finding['cloud_provider'] == 'AWS'
        assert finding['account_id'] == '123456789012'
        assert finding['account_name'] == 'Production AWS'
        
        print("\nAll enhanced fields present and correct!")
    else:
        print("No findings created")