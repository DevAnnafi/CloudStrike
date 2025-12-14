"""
CloudStrike - GCP Bucket Security Checker
-----------------------------------------

Purpose:
    Enumerate all GCP Cloud Storage buckets in a project and identify
    security misconfigurations and potential data exposure.

Checks:
    - Public access (allUsers / allAuthenticatedUsers)
    - Uniform Bucket-Level Access (UBLA)
    - Versioning
    - Logging
    - Optional: public objects
"""

import os
from google.cloud import storage

# Load GCP project ID from environment
project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
if not project_id:
    print("[!] ERROR: Set the environment variable GOOGLE_CLOUD_PROJECT")
    exit(1)

# Initialize the GCP Storage client
client = storage.Client(project=project_id)

print(f"[*] Starting GCP Bucket Security Check for project: {project_id}")

# List all buckets in the project
buckets = client.list_buckets()

for bucket in buckets:
    print("\n--------------------------------------------------")
    print(f"Bucket Name     : {bucket.name}")
    print(f"Location        : {bucket.location}")
    print(f"Storage Class   : {bucket.storage_class}")

    # Retrieve IAM policy
    policy = bucket.get_iam_policy(requested_policy_version=3)
    public_roles = []
    for binding in policy.bindings:
        members = binding.get("members", [])
        if "allUsers" in members or "allAuthenticatedUsers" in members:
            public_roles.append(binding["role"])
    if public_roles:
        print(f"[!!!] Public Access Detected! Roles: {public_roles}")
    else:
        print("[OK] No public access detected.")

    # Check UBLA
    if bucket.iam_configuration.uniform_bucket_level_access.enabled:
        print("[OK] Uniform Bucket-Level Access (UBLA) is enabled")
    else:
        print("[!] UBLA is NOT enabled")

    # Check versioning
    if bucket.versioning_enabled:
        print("[OK] Versioning is enabled")
    else:
        print("[!] Versioning is disabled")

    # Check logging
    if bucket.logging is not None and bucket.logging.get("logBucket"):
        print(f"[OK] Logging enabled to bucket: {bucket.logging['logBucket']}")
    else:
        print("[!] Logging is disabled")

    # Optional: Check a few objects for public ACL
    try:
        blobs = bucket.list_blobs(max_results=5)
        for blob in blobs:
            acl = blob.acl.get_entities()
            public_acl = [e for e in acl if e in ("allUsers", "allAuthenticatedUsers")]
            if public_acl:
                print(f"[!!!] Public object detected: {blob.name}")
    except Exception as e:
        print(f"[!] Could not list blobs for bucket {bucket.name}: {e}")

print("\n[*] GCP Bucket Security Check Completed")
