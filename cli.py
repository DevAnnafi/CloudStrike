# ---------------------------------------------------------------------------
# cli.py
# ---------------------------------------------------------------------------
# Purpose:
#   Entry point for the CloudStrike CLI.
#
#   Responsible for:
#     - Parsing command-line arguments
#     - Creating cloud sessions / clients
#     - Dispatching enabled modules (AWS, Azure, GCP)
#     - Aggregating findings
#     - Passing results to the reporting engine
# ---------------------------------------------------------------------------

import argparse
import sys

# AWS SDK
import boto3

# Azure / GCP modules
try:
    from azure.iam_enum import main as azure_iam_main
    from azure.metadata import main as azure_metadata_main
    from azure.storage_checker import main as azure_storage_main
except ImportError:
    azure_iam_main = azure_metadata_main = azure_storage_main = None

try:
    from gcp.iam_enum import main as gcp_iam_main
    from gcp.metadata import main as gcp_metadata_main
    from gcp.bucket_checker import main as gcp_bucket_main
except ImportError:
    gcp_iam_main = gcp_metadata_main = gcp_bucket_main = None

# Core CloudStrike utilities
from core.logger import get_logger
from core.report import write_report

# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="CloudStrike - Multi-Cloud Offensive Security Scanner"
    )

    # AWS flags
    parser.add_argument("--aws-iam", action="store_true", help="Enumerate IAM users, roles, and privilege escalation risks")
    parser.add_argument("--aws-ec2", action="store_true", help="Enumerate EC2 instances and misconfigurations")
    parser.add_argument("--aws-meta", action="store_true", help="Detect EC2 Instance Metadata Service (IMDS) issues")
    parser.add_argument("--aws-s3", action="store_true", help="Enumerate S3 buckets and detect public/misconfigured access")

    # Azure flags
    parser.add_argument("--azure-iam", action="store_true", help="Enumerate Azure IAM roles and users")
    parser.add_argument("--azure-meta", action="store_true", help="Enumerate Azure project metadata")
    parser.add_argument("--azure-storage", action="store_true", help="Enumerate Azure Storage accounts and blobs")

    # GCP flags
    parser.add_argument("--gcp-iam", action="store_true", help="Enumerate GCP IAM roles, bindings, and service accounts")
    parser.add_argument("--gcp-meta", action="store_true", help="Retrieve GCP project metadata")
    parser.add_argument("--gcp-bucket", action="store_true", help="Enumerate GCP buckets and check public access")

    # Output
    parser.add_argument(
        "--output",
        default="cloudstrike_report.json",
        help="Output report filename (default: cloudstrike_report.json)"
    )

    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    logger = get_logger()
    findings = []

    # ---------------------------------------------------------------------
    # AWS Session Initialization
    # ---------------------------------------------------------------------
    try:
        aws_session = boto3.Session()
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        sys.exit(1)

    # ---------------------------------------------------------------------
    # Module Dispatch
    # ---------------------------------------------------------------------

    # ----------------- AWS Modules -----------------
    if args.aws_iam:
        logger.info("[CLI] Running AWS IAM enumeration")
        from aws.iam_enum import run_iam_enum
        findings.extend(run_iam_enum(aws_session, logger))

    if args.aws_ec2:
        logger.info("[CLI] Running AWS EC2 enumeration")
        from aws.ec2_enum import run_ec2_enum
        findings.extend(run_ec2_enum(aws_session, logger))

    if args.aws_meta:
        logger.info("[CLI] Running AWS EC2 metadata checks")
        from aws.metadata import run_metadata_enum
        findings.extend(run_metadata_enum(aws_session, logger))

    if args.aws_s3:
        logger.info("[CLI] Running AWS S3 bucket checks")
        from aws.s3_checker import run_s3_enum
        findings.extend(run_s3_enum(aws_session, logger))

    # ----------------- Azure Modules -----------------
    if args.azure_iam:
        if azure_iam_main:
            logger.info("[CLI] Running Azure IAM enumeration")
            azure_iam_main()
        else:
            logger.warning("Azure IAM module not found")

    if args.azure_meta:
        if azure_metadata_main:
            logger.info("[CLI] Running Azure metadata enumeration")
            azure_metadata_main()
        else:
            logger.warning("Azure metadata module not found")

    if args.azure_storage:
        if azure_storage_main:
            logger.info("[CLI] Running Azure Storage enumeration")
            azure_storage_main()
        else:
            logger.warning("Azure Storage module not found")

    # ----------------- GCP Modules -----------------
    if args.gcp_iam:
        if gcp_iam_main:
            logger.info("[CLI] Running GCP IAM enumeration")
            gcp_iam_main()
        else:
            logger.warning("GCP IAM module not found")

    if args.gcp_meta:
        if gcp_metadata_main:
            logger.info("[CLI] Running GCP metadata enumeration")
            gcp_metadata_main()
        else:
            logger.warning("GCP metadata module not found")

    if args.gcp_bucket:
        if gcp_bucket_main:
            logger.info("[CLI] Running GCP bucket checks")
            gcp_bucket_main()
        else:
            logger.warning("GCP bucket module not found")

    # ---------------------------------------------------------------------
    # Reporting
    # ---------------------------------------------------------------------
    if findings:
        write_report(findings, args.output)
        logger.success(f"Report written to {args.output}")
    else:
        logger.warning("No findings collected. Did you enable any modules?")

# ---------------------------------------------------------------------------
# Execution Guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
