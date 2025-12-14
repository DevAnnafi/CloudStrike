# ---------------------------------------------------------------------------
# s3_checker.py
# ---------------------------------------------------------------------------
# Purpose:
#   Enumerate S3 buckets, detect public or misconfigured access, and
#   normalize findings for CloudStrike reporting.
# ---------------------------------------------------------------------------

import boto3
from botocore.exceptions import ClientError
from core.logger import print_info, print_warning, print_error, print_success
from core.utils import safe_execute, format_finding

# ---------------------------------------------------------------------------
# Dangerous Bucket Policies / ACLs
# ---------------------------------------------------------------------------
PUBLIC_ACL_GRANTS = [
    "AllUsers",
    "AuthenticatedUsers"
]

# ---------------------------------------------------------------------------
# Main S3 Enumeration Function
# ---------------------------------------------------------------------------
def enumerate_s3(session, logger, return_raw=False):
    """
    Enumerates all S3 buckets and checks for public access.
    
    Args:
        session: boto3.Session object
        logger: CloudStrike logger
        return_raw: If True, returns raw boto3 bucket objects
    Returns:
        List of normalized findings
    """
    s3 = session.client("s3")
    findings = []

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            creation_date = bucket.get("CreationDate")

            if return_raw:
                findings.append(bucket)
                continue

            # Initialize misconfig list
            misconfigs = []

            # Check Bucket ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("Type") == "Group":
                        uri = grantee.get("URI", "")
                        if any(public in uri for public in PUBLIC_ACL_GRANTS):
                            misconfigs.append("Bucket ACL Publicly Accessible")
            except ClientError as e:
                logger.warning(f"[S3] Could not retrieve ACL for bucket {bucket_name}: {e}")

            # Check Bucket Policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                # For simplicity, mark if policy exists (more parsing can be added)
                if policy.get("Policy"):
                    misconfigs.append("Bucket Policy Exists (review for public access)")
            except ClientError as e:
                if "NoSuchBucketPolicy" not in str(e):
                    logger.warning(f"[S3] Could not retrieve policy for bucket {bucket_name}: {e}")

            # Normalize finding
            bucket_finding = {
                "ResourceType": "S3 Bucket",
                "BucketName": bucket_name,
                "CreationDate": str(creation_date),
                "Misconfigurations": misconfigs
            }

            findings.append(bucket_finding)

    except ClientError as e:
        logger.error(f"[S3] Failed to enumerate buckets: {e}")

    return findings


# ---------------------------------------------------------------------------
# Convenience Wrapper for CLI
# ---------------------------------------------------------------------------
def run_s3_enum(session, logger, return_raw=False):
    logger.info("[S3] Starting S3 bucket enumeration")
    results = enumerate_s3(session, logger, return_raw=return_raw)
    logger.info(f"[S3] Enumeration complete. {len(results)} buckets analyzed")
    return results
