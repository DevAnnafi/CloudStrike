"""
CloudStrike - Azure IAM Enumeration Module
-----------------------------------------

Purpose:
    Enumerate Azure IAM (Entra ID + RBAC) configuration to identify
    users, groups, service principals, and role assignments.

Scope:
    - Azure AD (Entra ID):
        * Users
        * Groups
        * Service Principals
    - Azure RBAC:
        * Role Assignments
        * Role Definitions
        * Privileged roles (Owner, Contributor, Admin)

Authentication:
    Uses DefaultAzureCredential:
        - Azure CLI
        - Managed Identity
        - Environment credentials

NOTE:
    This script is READ-ONLY and safe for audit environments.
"""

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msgraph.core import GraphClient
from typing import Dict, List


# ---------------------------------------------------------
# Authentication
# ---------------------------------------------------------

def get_credential():
    """
    Obtain Azure credentials using the DefaultAzureCredential chain.

    This allows authentication via:
        - Azure CLI (az login)
        - Managed Identity
        - Environment variables

    Returns:
        DefaultAzureCredential object
    """
    return DefaultAzureCredential()


# ---------------------------------------------------------
# Azure RBAC Enumeration
# ---------------------------------------------------------

def enumerate_rbac_roles(subscription_id: str, credential) -> List[Dict]:
    """
    Enumerate RBAC role assignments for the given subscription.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object

    Returns:
        List of role assignment dictionaries
    """
    auth_client = AuthorizationManagementClient(
        credential=credential,
        subscription_id=subscription_id
    )

    print("\n[*] Enumerating Azure RBAC Role Assignments...\n")

    findings = []

    # Retrieve all role assignments in the subscription
    for assignment in auth_client.role_assignments.list():
        role_info = {
            "principal_id": assignment.principal_id,
            "role_definition_id": assignment.role_definition_id,
            "scope": assignment.scope
        }

        print(f"Principal ID       : {assignment.principal_id}")
        print(f"Role Definition ID : {assignment.role_definition_id}")
        print(f"Scope              : {assignment.scope}")
        print("-" * 60)

        findings.append(role_info)

    return findings


def enumerate_role_definitions(subscription_id: str, credential) -> Dict[str, str]:
    """
    Map Role Definition IDs to human-readable role names.

    Args:
        subscription_id (str): Azure subscription ID
        credential: Azure credential object

    Returns:
        Dictionary mapping role_definition_id -> role_name
    """
    auth_client = AuthorizationManagementClient(
        credential=credential,
        subscription_id=subscription_id
    )

    print("\n[*] Enumerating Role Definitions...\n")

    role_map = {}

    for role in auth_client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
        role_map[role.id] = role.role_name
        print(f"Role Name: {role.role_name}")
        print(f"Role ID  : {role.id}")
        print("-" * 60)

    return role_map


# ---------------------------------------------------------
# Azure AD (Entra ID) Enumeration
# ---------------------------------------------------------

def get_graph_client(credential):
    """
    Initialize Microsoft Graph client.

    Args:
        credential: Azure credential object

    Returns:
        GraphClient instance
    """
    return GraphClient(credential=credential)


def enumerate_users(graph_client):
    """
    Enumerate Azure AD users.

    Args:
        graph_client: Microsoft Graph client
    """
    print("\n[*] Enumerating Azure AD Users...\n")

    response = graph_client.get("/users")
    users = response.json().get("value", [])

    for user in users:
        print(f"User Display Name : {user.get('displayName')}")
        print(f"User Principal   : {user.get('userPrincipalName')}")
        print(f"User ID          : {user.get('id')}")
        print("-" * 60)


def enumerate_groups(graph_client):
    """
    Enumerate Azure AD groups.

    Args:
        graph_client: Microsoft Graph client
    """
    print("\n[*] Enumerating Azure AD Groups...\n")

    response = graph_client.get("/groups")
    groups = response.json().get("value", [])

    for group in groups:
        print(f"Group Name : {group.get('displayName')}")
        print(f"Group ID   : {group.get('id')}")
        print("-" * 60)


def enumerate_service_principals(graph_client):
    """
    Enumerate Azure AD service principals (App Registrations).

    Args:
        graph_client: Microsoft Graph client
    """
    print("\n[*] Enumerating Service Principals...\n")

    response = graph_client.get("/servicePrincipals")
    sps = response.json().get("value", [])

    for sp in sps:
        print(f"Service Principal Name : {sp.get('displayName')}")
        print(f"App ID                : {sp.get('appId')}")
        print(f"Object ID             : {sp.get('id')}")
        print("-" * 60)


# ---------------------------------------------------------
# Privileged Role Detection
# ---------------------------------------------------------

def identify_privileged_roles(rbac_assignments: List[Dict], role_definitions: Dict[str, str]):
    """
    Identify principals with high-risk roles.

    High-risk roles include:
        - Owner
        - Contributor
        - Global Administrator
        - Privileged Role Administrator

    Args:
        rbac_assignments (list): RBAC assignment data
        role_definitions (dict): Role ID -> Role Name mapping
    """
    print("\n[*] Identifying Privileged Role Assignments...\n")

    high_risk_roles = {
        "Owner",
        "Contributor",
        "Global Administrator",
        "Privileged Role Administrator"
    }

    for assignment in rbac_assignments:
        role_name = role_definitions.get(assignment["role_definition_id"], "Unknown")

        if role_name in high_risk_roles:
            print("[!!!] HIGH RISK ROLE DETECTED")
            print(f"Principal ID : {assignment['principal_id']}")
            print(f"Role Name   : {role_name}")
            print(f"Scope       : {assignment['scope']}")
            print("-" * 60)


# ---------------------------------------------------------
# Main Execution
# ---------------------------------------------------------

def main():
    """
    Entry point for Azure IAM enumeration.
    """
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")

    if not subscription_id:
        print("[!] ERROR: AZURE_SUBSCRIPTION_ID environment variable not set.")
        return

    print("[*] Starting CloudStrike Azure IAM Enumeration")
    print(f"[*] Subscription ID: {subscription_id}")

    credential = get_credential()

    # RBAC Enumeration
    rbac_assignments = enumerate_rbac_roles(subscription_id, credential)
    role_definitions = enumerate_role_definitions(subscription_id, credential)

    # Privilege Analysis
    identify_privileged_roles(rbac_assignments, role_definitions)

    # Azure AD Enumeration
    graph_client = get_graph_client(credential)
    enumerate_users(graph_client)
    enumerate_groups(graph_client)
    enumerate_service_principals(graph_client)

    print("\n[*] Azure IAM Enumeration Completed Successfully")


if __name__ == "__main__":
    main()
