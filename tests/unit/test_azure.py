import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest
from unittest.mock import patch, MagicMock
from scanners.azure.storage_checker import StorageChecker
from scanners.azure.iam_analyzer import RBACAnalyzer
from scanners.azure.metadata_probe import MetaDataProbe

def test_storage_public_container():
    with patch('scanners.azure.storage_checker.StorageManagementClient') as mock_client:
        mock_account = MagicMock()
        mock_account.name = "test-storage"
        mock_account.id = "/subscriptions/xxx/resourceGroups/test-rg/providers/..."
        
        mock_container = MagicMock()
        mock_container.name = "public-container"
        mock_container.public_access = "Container" 
        
        mock_client.return_value.storage_accounts.list.return_value = [mock_account]
        mock_client.return_value.blob_containers.list.return_value = [mock_container]
        
        scanner = StorageChecker("fake-sub-id")
        scanner.scan()
        
        assert len(scanner.findings) == 1
        assert "public" in scanner.findings[0]["title"].lower()

def test_rbac_owner_role():
    with patch('scanners.azure.iam_analyzer.AuthorizationManagementClient') as mock_client:
        mock_binding = MagicMock()
        mock_binding.role_definition_id = "/subscriptions/.../roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  
        mock_binding.principal_id = "test-principal-123"
        mock_binding.scope = "/subscriptions/test-sub"
        
        mock_client.return_value.role_assignments.list.return_value = [mock_binding]
        
        scanner = RBACAnalyzer("fake-sub-id")
        scanner.scan()
        
        assert len(scanner.findings) == 1
        assert "Overly Permissive" in scanner.findings[0]["title"]

def test_metadata_accessible():
    with patch('scanners.azure.metadata_probe.requests.get') as mock_get:
        mock_get.return_value.status_code = 200
        
        scanner = MetaDataProbe()
        scanner.check_imds_version()
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0]["severity"] == "critical"