"""
CloudStrike - Azure Metadata Enumeration Module
-----------------------------------------------

Purpose:
    Collect high-value Azure environment metadata that provides
    situational awareness for security audits and threat modeling.

Enumerated Metadata:
    - Subscription information
    - Tenant (Entra ID) information
    - Resource groups
    - Locations (regions)
    - Azure environment context

Use Cases:
    - Cloud posture assessment
    - Attack surface mapping
    - Asset inventory
    - IAM scoping validation

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
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from typing import Dict, List


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
# Subscription & Tenant Metadata
# ---------------------------------------------------------

def enumerate_subscriptions(credential) -> List[Dict]:
    """
    Enumerate all accessible Azure subscriptions.

    Args:
        credential: Azure credential object

    Returns:
        List of subscription metadata dictionaries
    """
    print("\n[*] Enumerating Azure Subscriptions...\n")

    sub_client = SubscriptionClient(credential)
    subscriptions = []

    for sub in sub_client.subscriptions.list():
        sub_info = {
            "subscription_id": sub.subscription_id,
            "display_name": sub.display_name,
            "state": sub.state
        }

        print(f"Subscription Name : {sub.display_name}")
        print(f"Subscription ID   : {sub.subscription_id}")
        print(f"State             : {sub.state}")
        print("-" * 60)

        subscriptions.append(sub_info)

    return subscriptions


def enumerate_tenant_info() -> Dict:
    """
    Enumerate Entra ID (Azure AD) tenant metadata.

    NOTE:
        Tenant ID is inferred from environment or Azure CLI context.

    Returns:
        Dictionary containing tenant metadata
    """
    print("\n[*] Enumerating Tenant Information...\n")

    tenant_id = os.environ.get("AZURE_TENANT_ID", "Unknown")

    tenant_info = {
        "tenant_id": tenant_id
    }

    print(f"Tenant ID: {tenant_id}")
    print("-" * 60)

    return tenant_info


# ---------------------------------------------------------
# Resource Group & Region Metadata
# ---------------------------------------------------------

def enumerate_resource_groups(subscription_id: str, credential) -> List[Dict]:
    """
    Enumerate all resource groups in a subscription.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object

    Returns:
        List of resource group metadata dictionaries
    """
    print("\n[*] Enumerating Resource Groups...\n")

    rg_client = ResourceManagementClient(credential, subscription_id)
    resource_groups = []

    for rg in rg_client.resource_groups.list():
        rg_info = {
            "name": rg.name,
            "location": rg.location,
            "id": rg.id
        }

        print(f"Resource Group : {rg.name}")
        print(f"Location       : {rg.location}")
        print(f"ID             : {rg.id}")
        print("-" * 60)

        resource_groups.append(rg_info)

    return resource_groups


def enumerate_locations(subscription_id: str, credential) -> List[str]:
    """
    Enumerate Azure regions available to the subscription.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object

    Returns:
        List of region names
    """
    print("\n[*] Enumerating Azure Regions...\n")

    sub_client = SubscriptionClient(credential)
    locations = []

    for location in sub_client.subscriptions.list_locations(subscription_id):
        print(f"Region: {location.name}")
        locations.append(location.name)

    print("-" * 60)
    return locations


# ---------------------------------------------------------
# Environment Context
# ---------------------------------------------------------

def get_environment_context() -> Dict:
    """
    Capture local Azure execution context.

    Returns:
        Dictionary of environment context values
    """
    print("\n[*] Capturing Azure Execution Context...\n")

    context = {
        "azure_subscription_id": os.environ.get("AZURE_SUBSCRIPTION_ID"),
        "azure_tenant_id": os.environ.get("AZURE_TENANT_ID"),
        "azure_client_id": os.environ.get("AZURE_CLIENT_ID"),
        "execution_user": os.environ.get("USER") or os.environ.get("USERNAME")
    }

    for key, value in context.items():
        print(f"{key}: {value}")

    print("-" * 60)
    return context


# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------

def main():
    """
    Entry point for Azure metadata enumeration.
    """
    print("[*] Starting CloudStrike Azure Metadata Enumeration")

    credential = get_credential()

    # Subscription metadata
    subscriptions = enumerate_subscriptions(credential)

    # Tenant metadata
    tenant_info = enumerate_tenant_info()

    # If a subscription is explicitly set, enumerate deeper
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if subscription_id:
        enumerate_resource_groups(subscription_id, credential)
        enumerate_locations(subscription_id, credential)
    else:
        print("[!] AZURE_SUBSCRIPTION_ID not set — skipping RG and region enumeration.")

    # Execution context
    get_environment_context()

    print("\n[*] Azure Metadata Enumeration Completed Successfully")


if __name__ == "__main__":
    main()
