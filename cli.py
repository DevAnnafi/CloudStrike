# ---------------------------------------------------------------------------
# cli.py
# ---------------------------------------------------------------------------
# Purpose:
#   Entry point for the CloudStrike CLI.
#
#   Responsible for:
#     - Parsing command-line arguments
#     - Creating AWS sessions
#     - Dispatching enabled modules
#     - Aggregating findings
#     - Passing results to the reporting engine
# ---------------------------------------------------------------------------

import argparse
import boto3
import sys

# CloudStrike core utilities
from core.logger import get_logger
from core.report import write_report

# AWS modules
from aws.iam_enum import run_iam_enum
from aws.ec2_enum import run_ec2_enum
from aws.metadata import run_metadata_enum
from aws.s3_checker import run_s3_enum


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
        session = boto3.Session()
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        sys.exit(1)

    # ---------------------------------------------------------------------
    # Module Dispatch
    # ---------------------------------------------------------------------

    if args.aws_iam:
        logger.info("[CLI] Running AWS IAM enumeration")
        findings.extend(run_iam_enum(session, logger))

    if args.aws_ec2:
        logger.info("[CLI] Running AWS EC2 enumeration")
        findings.extend(run_ec2_enum(session, logger))

    if args.aws_meta:
        logger.info("[CLI] Running AWS EC2 metadata checks")
        findings.extend(run_metadata_enum(session, logger))

    if args.aws_s3:
        logger.info("[CLI] Running AWS S3 bucket checks")
        findings.extend(run_s3_enum(session, logger))

    if not findings:
        logger.warning("No findings collected. Did you enable any modules?")
        return

    # ---------------------------------------------------------------------
    # Reporting
    # ---------------------------------------------------------------------

    write_report(findings, args.output)
    logger.success(f"Report written to {args.output}")


# ---------------------------------------------------------------------------
# Execution Guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
