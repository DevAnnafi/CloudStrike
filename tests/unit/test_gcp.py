import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest
from unittest.mock import patch, MagicMock
from scanners.gcp.bucket_checker import BucketScanner
from scanners.gcp.iam_scanner import IAMScanner
from scanners.gcp.metadata_scanner import MetaDataScanner

def test_bucket_public_iam_policy():
    with patch("scanners.gcp.bucket_checker.storage.Client") as mock_client:
        mock_bucket = MagicMock()
        mock_bucket.name = "public-bucket"
        
        mock_binding = {'members': ['allUsers']}  
        
        mock_policy = MagicMock()
        mock_policy.bindings = [mock_binding]
        
        mock_bucket.get_iam_policy.return_value = mock_policy
        mock_client.return_value.list_buckets.return_value = [mock_bucket]
        
        scanner = BucketScanner("fake-project-id")
        scanner.scan()
        
        assert len(scanner.findings) == 1
        assert "Public GCP Storage Bucket" in scanner.findings[0]["title"]

def test_iam_owner_role():
    with patch('scanners.gcp.iam_scanner.resourcemanager_v3.ProjectsClient') as mock_client_class:
        mock_binding = MagicMock()
        mock_binding.role = "roles/owner"
        mock_binding.members = ["user:test@example.com"]
        
        mock_policy = MagicMock()
        mock_policy.bindings = [mock_binding]
        
        mock_instance = MagicMock()
        mock_instance.get_iam_policy.return_value = mock_policy
        mock_client_class.return_value = mock_instance
        
        scanner = IAMScanner("fake-project-id")

        scanner.check_binding(mock_binding)
        
        assert len(scanner.findings) == 1
        assert "Overly Permissive" in scanner.findings[0]["title"]

def test_metadata_accessible():
    with patch('scanners.gcp.metadata_scanner.requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        
        scanner = MetaDataScanner()
        scanner.check_imds_version()
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "critical"