"""
CloudStrike - GCP IAM Enumeration Module
----------------------------------------

Purpose:
    Enumerate IAM roles, bindings, and service accounts in a GCP project
    to identify privileged accounts and potential misconfigurations.

Checks:
    - Project IAM policy bindings (roles & members)
    - Detect public roles (allUsers / allAuthenticatedUsers)
    - Identify high-privileged roles (Owner, Editor, Service Account Admin)
    - List all service accounts with basic metadata
"""

import os
from google.cloud import resourcemanager_v3
from google.cloud import iam_v1

# Load GCP project ID from environment
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
if not project_id:
    print("[!] ERROR: Set the environment variable GOOGLE_CLOUD_PROJECT")
    exit(1)

print(f"[*] Starting GCP IAM Enumeration for project: {project_id}")

# Initialize Resource Manager client for project IAM policy
rm_client = resourcemanager_v3.ProjectsClient()

# Retrieve IAM policy for the project
policy = rm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})

# Define high-privilege roles to flag
high_priv_roles = {"roles/owner", "roles/editor", "roles/iam.serviceAccountAdmin", "roles/iam.securityAdmin"}

print("\n[*] Project IAM Policy Bindings:")
for binding in policy.bindings:
    role = binding.role
    members = binding.members
    print(f"\nRole: {role}")
    print(f"Members: {members}")

    # Check for public access
    if "allUsers" in members or "allAuthenticatedUsers" in members:
        print("[!!!] Public access detected!")

    # Check for high-privilege roles
    if role in high_priv_roles:
        print("[!!!] High-privilege role detected!")

# Initialize IAM client to list service accounts
iam_client = iam_v1.IAMClient()

# List all service accounts in the project
service_accounts = iam_client.list_service_accounts(request={"name": f"projects/{project_id}"})

print("\n[*] Service Accounts:")
for sa in service_accounts:
    print(f"\nService Account Name  : {sa.display_name}")
    print(f"Email                 : {sa.email}")
    print(f"Unique ID             : {sa.unique_id}")

    # Optional: List keys for the service account
    try:
        keys = iam_client.list_service_account_keys(
            request={"name": f"projects/{project_id}/serviceAccounts/{sa.email}"}
        )
        if keys.keys:
            for key in keys.keys:
                print(f"Key ID: {key.name}, Created At: {key.valid_after_time}")
        else:
            print("No keys found")
    except Exception as e:
        print(f"[!] Could not list keys for {sa.email}: {e}")

print("\n[*] GCP IAM Enumeration Completed")
