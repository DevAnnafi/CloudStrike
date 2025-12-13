# ---------------------------------------------------------------------------
# metadata.py
# ---------------------------------------------------------------------------
# Purpose:
#   This module inspects EC2 instance metadata configuration and detects
#   insecure Instance Metadata Service (IMDS) settings.
#
#   The EC2 Instance Metadata Service is a common cloud attack vector used
#   to steal IAM role credentials from compromised workloads.
#
#   This module identifies:
#     - Instances with IMDSv1 enabled
#     - Instances where IMDS tokens are optional
#     - Excessive metadata hop limits
#     - Instances vulnerable to SSRF-based credential theft
#
#   Findings are normalized into CloudStrike-compatible output objects.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Detection Thresholds
# ---------------------------------------------------------------------------

# IMDSv2 requires session tokens.
# If HttpTokens is "optional", IMDSv1 is effectively enabled.
INSECURE_TOKEN_SETTING = "optional"

# Hop limits greater than 1 allow metadata access beyond the local instance
# and increase SSRF exploitability.
MAX_SAFE_HOP_LIMIT = 1


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def enumerate_metadata(session, logger):
    """
    Enumerate EC2 instances and inspect Instance Metadata Service (IMDS)
    configuration for security weaknesses.

    Args:
        session (boto3.Session): Injected AWS session from CloudStrike CLI
        logger: Centralized CloudStrike logger

    Returns:
        list: Normalized metadata misconfiguration findings
    """

    ec2 = session.client("ec2")
    findings = []

    logger.info("Starting EC2 metadata configuration enumeration")

    try:
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    instance_id = instance.get("InstanceId")
                    region = ec2.meta.region_name

                    metadata_options = instance.get("MetadataOptions", {})

                    http_endpoint = metadata_options.get("HttpEndpoint")
                    http_tokens = metadata_options.get("HttpTokens")
                    hop_limit = metadata_options.get("HttpPutResponseHopLimit")

                    # Skip instances with metadata endpoint disabled
                    if http_endpoint == "disabled":
                        continue

                    # ------------------------------------------------------------------
                    # IMDSv1 Detection (HttpTokens = optional)
                    # ------------------------------------------------------------------

                    if http_tokens == INSECURE_TOKEN_SETTING:
                        findings.append({
                            "service": "AWS EC2",
                            "resource_type": "EC2 Instance",
                            "resource_id": instance_id,
                            "region": region,
                            "severity": "HIGH",
                            "issue": "IMDSv1 enabled (HttpTokens optional)",
                            "evidence": {
                                "HttpTokens": http_tokens,
                                "HttpEndpoint": http_endpoint
                            },
                            "recommendation": (
                                "Require IMDSv2 by setting HttpTokens to 'required' "
                                "to prevent credential theft via SSRF attacks."
                            )
                        })

                    # ------------------------------------------------------------------
                    # Hop Limit Misconfiguration
                    # ------------------------------------------------------------------

                    if hop_limit is not None and hop_limit > MAX_SAFE_HOP_LIMIT:
                        findings.append({
                            "service": "AWS EC2",
                            "resource_type": "EC2 Instance",
                            "resource_id": instance_id,
                            "region": region,
                            "severity": "MEDIUM",
                            "issue": "Excessive IMDS hop limit",
                            "evidence": {
                                "HttpPutResponseHopLimit": hop_limit
                            },
                            "recommendation": (
                                "Reduce the metadata hop limit to 1 to restrict "
                                "metadata access to the local instance only."
                            )
                        })

        logger.info("Completed EC2 metadata configuration enumeration")

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")

        logger.warning(
            f"Failed to enumerate EC2 metadata configuration "
            f"(error: {error_code})"
        )

    return findings


# ---------------------------------------------------------------------------
# Optional CLI Wrapper
# ---------------------------------------------------------------------------

def run_metadata_enum(session, logger):
    """
    Wrapper used by the CloudStrike CLI.

    Args:
        session (boto3.Session): Injected AWS session
        logger: Centralized CloudStrike logger

    Returns:
        list: Metadata misconfiguration findings
    """
    logger.info("Running EC2 metadata security checks")
    return enumerate_metadata(session, logger)
