from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from core.enums import CloudProvider, Severity, FindingType


class StorageChecker():
    def __init__(self, subscription_id=None, account_name=None):
        self.findings = []
        self.subscription_id = subscription_id
        self.account_name = account_name or "Default"
        
        self.credential = DefaultAzureCredential()
        self.storage_client = StorageManagementClient(self.credential, subscription_id)

    def scan(self):
        try:
            storage_accounts = self.storage_client.storage_accounts.list()
            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]
                containers = self.storage_client.blob_containers.list(resource_group, account_name)
                for container in containers:
                    if container.public_access is not None:
                        self.check_container_access(container.name, account_name, container.public_access)
        except:
            pass

        return self.findings
 

    def check_container_access(self, container_name, account_name, public_access):
        self.findings.append({
            "severity" : Severity.CRITICAL.value,
            "title" : "Public Azure Blob Container",
            "resource" : f"{account_name}/{container_name}",
            "cloud_provider": "Azure", 
            "account_id": self.subscription_id,  
            "account_name": self.account_name,
            "description" : f"Container has public access level:{public_access}"
        })