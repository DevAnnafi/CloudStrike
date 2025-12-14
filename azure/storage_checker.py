"""
CloudStrike - Azure Storage Security Checker
--------------------------------------------

Purpose:
    Enumerate Azure Storage Accounts and identify common
    security misconfigurations and exposure risks.

Checked Areas:
    - Storage account inventory
    - Public blob access configuration
    - HTTPS enforcement
    - Secure transfer requirement
    - Network access rules
    - Blob container public access level

Use Cases:
    - Cloud security posture management (CSPM)
    - Data exposure risk analysis
    - Compliance validation (CIS, NIST)
    - Attack surface mapping

Authentication:
    Uses DefaultAzureCredential:
        - Azure CLI
        - Managed Identity
        - Environment variables

NOTE:
    This module is READ-ONLY and safe for production environments.
"""

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from typing import List, Dict


# ---------------------------------------------------------
# Authentication
# ---------------------------------------------------------

def get_credential():
    """
    Acquire Azure credentials using DefaultAzureCredential.

    Returns:
        DefaultAzureCredential object
    """
    return DefaultAzureCredential()


# ---------------------------------------------------------
# Storage Account Enumeration
# ---------------------------------------------------------

def enumerate_storage_accounts(subscription_id: str, credential) -> List[Dict]:
    """
    Enumerate all storage accounts in a subscription.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object

    Returns:
        List of storage account metadata dictionaries
    """
    print("\n[*] Enumerating Azure Storage Accounts...\n")

    storage_client = StorageManagementClient(credential, subscription_id)
    accounts = []

    for account in storage_client.storage_accounts.list():
        account_info = {
            "name": account.name,
            "id": account.id,
            "location": account.location,
            "resource_group": account.id.split("/")[4],
            "kind": account.kind,
            "sku": account.sku.name
        }

        print(f"Storage Account : {account.name}")
        print(f"Resource Group  : {account_info['resource_group']}")
        print(f"Location        : {account.location}")
        print(f"Kind            : {account.kind}")
        print(f"SKU             : {account.sku.name}")
        print("-" * 60)

        accounts.append(account_info)

    return accounts


# ---------------------------------------------------------
# Storage Account Security Checks
# ---------------------------------------------------------

def check_storage_account_security(subscription_id: str, credential, account: Dict):
    """
    Evaluate security settings for a single storage account.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object
        account (dict): Storage account metadata
    """
    storage_client = StorageManagementClient(credential, subscription_id)

    rg = account["resource_group"]
    name = account["name"]

    print(f"\n[*] Checking security configuration for: {name}\n")

    props = storage_client.storage_accounts.get_properties(rg, name)

    # HTTPS enforcement
    if not props.enable_https_traffic_only:
        print("[!!!] HTTPS NOT enforced")
    else:
        print("[OK] HTTPS enforced")

    # Secure transfer
    if not props.enable_https_traffic_only:
        print("[!!!] Secure transfer disabled")
    else:
        print("[OK] Secure transfer enabled")

    # Public blob access
    if props.allow_blob_public_access:
        print("[!!!] Public blob access ALLOWED")
    else:
        print("[OK] Public blob access disabled")

    # Network rules
    network_rules = props.network_rule_set
    if network_rules and network_rules.default_action == "Allow":
        print("[!!!] Storage account accessible from ALL networks")
    else:
        print("[OK] Network access restricted")

    print("-" * 60)


# ---------------------------------------------------------
# Blob Container Exposure Checks
# ---------------------------------------------------------

def enumerate_blob_containers(account: Dict, credential):
    """
    Enumerate blob containers and identify public access.

    Args:
        account (dict): Storage account metadata
        credential: Azure credential object
    """
    account_name = account["name"]
    account_url = f"https://{account_name}.blob.core.windows.net"

    print(f"\n[*] Enumerating blob containers for: {account_name}\n")

    try:
        blob_service = BlobServiceClient(
            account_url=account_url,
            credential=credential
        )

        containers = blob_service.list_containers()

        for container in containers:
            public_access = container.public_access

            print(f"Container Name : {container.name}")
            print(f"Public Access  : {public_access}")

            if public_access:
                print("[!!!] PUBLICLY ACCESSIBLE CONTAINER DETECTED")

            print("-" * 60)

    except Exception as e:
        print(f"[!] Unable to enumerate containers for {account_name}: {str(e)}")


# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------

def main():
    """
    Entry point for Azure storage security checks.
    """
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")

    if not subscription_id:
        print("[!] ERROR: AZURE_SUBSCRIPTION_ID environment variable not set.")
        return

    print("[*] Starting CloudStrike Azure Storage Security Checks")
    print(f"[*] Subscription ID: {subscription_id}")

    credential = get_credential()

    # Enumerate storage accounts
    accounts = enumerate_storage_accounts(subscription_id, credential)

    # Perform security checks on each storage account
    for account in accounts:
        check_storage_account_security(subscription_id, credential, account)
        enumerate_blob_containers(account, credential)

    print("\n[*] Azure Storage Security Checks Completed Successfully")


if __name__ == "__main__":
    main()
