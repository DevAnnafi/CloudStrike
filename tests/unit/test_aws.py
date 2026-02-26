import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest
import json
from unittest.mock import patch, MagicMock
from scanners.aws.s3_checker import S3Scanner

def test_s3_public_access_finding():
    with patch('scanners.aws.s3_checker.boto3.client') as mock_boto:
        mock_boto.return_value.get_public_access_block.side_effect = Exception("Not configured")
        scanner = S3Scanner()
        scanner.check_public_access("fake-bucket")
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "critical"        

def test_s3_encryption_finding():
    with patch('scanners.aws.s3_checker.boto3.client') as mock_boto:
        mock_boto.return_value.get_bucket_encryption.side_effect = Exception("Not configured")
        scanner = S3Scanner()
        scanner.check_encryption("fake-bucket")
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "high"

def test_s3_no_finding_when_secure():
    with patch('scanners.aws.s3_checker.boto3.Session') as mock_session:
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
        
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    
        mock_session.return_value.client.side_effect = lambda service: mock_sts if service == 'sts' else mock_s3
        
        scanner = S3Scanner()
        scanner.check_public_access("fake-bucket")
        assert len(scanner.findings) == 0

def test_s3_policy_public_star_principal():
    with patch('scanners.aws.s3_checker.boto3.Session') as mock_session:
        mock_s3 = MagicMock()
        
        public_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*"
                }
            ]
        }
        
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps(public_policy)
        }
        
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        mock_session.return_value.client.side_effect = lambda service: mock_sts if service == 'sts' else mock_s3
        
        scanner = S3Scanner()
        scanner.check_policy("public-bucket")
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["title"] == "Public S3 Bucket via Policy"
        assert scanner.findings[0]["resource"] == "public-bucket"


def test_s3_policy_public_aws_wildcard():
    with patch('scanners.aws.s3_checker.boto3.Session') as mock_session:
        mock_s3 = MagicMock()
        
        public_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                }
            ]
        }
        
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps(public_policy)
        }
        
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        mock_session.return_value.client.side_effect = lambda service: mock_sts if service == 'sts' else mock_s3
        
        scanner = S3Scanner()
        scanner.check_policy("public-bucket")
        
        assert len(scanner.findings) == 1

def test_s3_policy_private_bucket():
    with patch('scanners.aws.s3_checker.boto3.client') as mock_boto:
        mock_client = mock_boto.return_value

        private_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"}
                }
            ]
        }

        mock_client.get_bucket_policy.return_value = {
            "Policy": json.dumps(private_policy)
        }

        scanner = S3Scanner()
        scanner.check_policy("private-bucket")

        assert len(scanner.findings) == 0


def test_s3_policy_no_policy_exception():
    with patch('scanners.aws.s3_checker.boto3.client') as mock_boto:
        mock_client = mock_boto.return_value
        mock_client.get_bucket_policy.side_effect = Exception("No policy")

        scanner = S3Scanner()
        scanner.check_policy("no-policy-bucket")

        
        assert len(scanner.findings) == 0