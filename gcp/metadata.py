"""
CloudStrike - GCP Project Metadata Module
-----------------------------------------

Purpose:
    Retrieve metadata for a GCP project, including:
        - Project info (ID, name, number)
        - Labels
        - Lifecycle state
        - Folder and organization hierarchy
        - Billing info (if accessible)
        - Service enablement status (optional)

Authentication:
    - Uses Application Default Credentials (ADC)
    - Supports gcloud CLI login or service account

Scope:
    - Read-only audit for CloudStrike purposes
"""

import os
from google.cloud import resourcemanager_v3
from google.cloud import billing_v1

# Step 1: Load project ID from environment
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
if not project_id:
    print("[!] ERROR: Set the environment variable GOOGLE_CLOUD_PROJECT")
    exit(1)

print(f"[*] Gathering metadata for project: {project_id}")

# Step 2: Initialize Resource Manager client
rm_client = resourcemanager_v3.ProjectsClient()

# Step 3: Get project info
try:
    project = rm_client.get_project(name=f"projects/{project_id}")
    print("\n[*] Project Information:")
    print(f"Project ID       : {project.project_id}")
    print(f"Project Name     : {project.display_name}")
    print(f"Project Number   : {project.project_number}")
    print(f"Lifecycle State  : {project.state.name}")
    print(f"Labels           : {project.labels if project.labels else 'None'}")
except Exception as e:
    print(f"[!] Could not retrieve project info: {e}")

# Step 4: Get folder and organization info (if available)
if project.parent:
    print(f"Parent Type      : {project.parent.type_}")
    print(f"Parent ID        : {project.parent.id}")

# Step 5: Initialize Cloud Billing client to get billing info
try:
    billing_client = billing_v1.CloudBillingClient()
    billing_info = billing_client.get_project_billing_info(name=f"projects/{project_id}")
    if billing_info.billing_account_name:
        print("\n[*] Billing Information:")
        print(f"Billing Account : {billing_info.billing_account_name}")
        print(f"Billing Enabled : {billing_info.billing_enabled}")
    else:
        print("[*] No billing account associated with this project")
except Exception as e:
    print(f"[!] Could not retrieve billing info: {e}")

# Step 6: Optional - List enabled services for the project
try:
    services = rm_client.list_services(parent=f"projects/{project_id}")
    print("\n[*] Enabled Services:")
    for svc in services:
        print(f"- {svc.config.name}")
except Exception as e:
    print(f"[!] Could not list services: {e}")

print("\n[*] GCP Project Metadata Gathering Completed")
