import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest
from unittest.mock import patch, MagicMock
from scanners.aws.s3_checker import S3Scanner

def test_s3_public_access_finding():
    with patch('boto3.client') as mock_boto:
        mock_boto.return_value.get_public_access_block.side_effect = Exception("Not configured")
        scanner = S3Scanner()
        scanner.check_public_access("fake-bucket")
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "critical"        

def test_s3_encryption_finding():
    with patch('boto3.client') as mock_boto:
        mock_boto.return_value.get_bucket_encryption.side_effect = Exception("Not configure")
        scanner = S3Scanner()
        scanner.check_encryption("fake-bucket")
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "medium"

def test_s3_no_finding_when_secure():
    with patch('boto3.client') as mock_boto:
        mock_boto.return_value.get_public_access = {
        'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
        }
        scanner = S3Scanner()
        scanner.check_public_access("fake-bucket")
        assert len(scanner.findings) == 0
