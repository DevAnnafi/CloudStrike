# ---------------------------------------------------------------------------
# iam_enum.py
# ---------------------------------------------------------------------------
# Purpose:
#   Enumerate AWS IAM resources and detect high‑risk misconfigurations and
#   privilege escalation vectors.
#
#   IAM is a GLOBAL AWS service (not region‑scoped).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from core.logger import (
    print_info,
    print_warning,
    print_error,
    print_success
)

from core.utils import (
    safe_execute,
    format_finding
)


# ---------------------------------------------------------------------------
# Constants and Detection Rules
# ---------------------------------------------------------------------------

DANGEROUS_ACTIONS = {
    "*",
    "iam:*",
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "sts:AssumeRole"
}

DANGEROUS_RESOURCES = {"*"}


# ---------------------------------------------------------------------------
# Helper: Analyze Policy Document
# ---------------------------------------------------------------------------

def analyze_policy_document(policy_document):
    misconfigs = []

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            if action in DANGEROUS_ACTIONS:
                misconfigs.append(f"Dangerous IAM Action Allowed: {action}")

        for resource in resources:
            if resource in DANGEROUS_RESOURCES:
                misconfigs.append("Wildcard Resource Allowed ('*')")

    return list(set(misconfigs))


# ---------------------------------------------------------------------------
# Enumerate IAM Users
# ---------------------------------------------------------------------------

def enumerate_users(iam, logger):
    findings = []

    try:
        users = iam.list_users().get("Users", [])

        for user in users:
            username = user["UserName"]
            misconfigs = []

            attached = iam.list_attached_user_policies(UserName=username)
            for pol in attached.get("AttachedPolicies", []):
                policy = iam.get_policy(PolicyArn=pol["PolicyArn"])
                version_id = policy["Policy"]["DefaultVersionId"]

                version = iam.get_policy_version(
                    PolicyArn=pol["PolicyArn"],
                    VersionId=version_id
                )

                misconfigs.extend(
                    analyze_policy_document(version["PolicyVersion"]["Document"])
                )

            inline_policies = iam.list_user_policies(UserName=username)
            for pname in inline_policies.get("PolicyNames", []):
                pol = iam.get_user_policy(UserName=username, PolicyName=pname)
                misconfigs.extend(analyze_policy_document(pol["PolicyDocument"]))

            findings.append(format_finding(
                resource_type="IAM User",
                resource_id=username,
                details={
                    "Arn": user["Arn"],
                    "CreateDate": str(user["CreateDate"])
                },
                misconfigurations=misconfigs
            ))

    except ClientError as e:
        print_warning(f"[IAM] User enumeration failed: {e}")

    return findings


# ---------------------------------------------------------------------------
# Enumerate IAM Groups
# ---------------------------------------------------------------------------

def enumerate_groups(iam, logger):
    findings = []

    try:
        groups = iam.list_groups().get("Groups", [])

        for group in groups:
            group_name = group["GroupName"]
            misconfigs = []

            attached = iam.list_attached_group_policies(GroupName=group_name)
            for pol in attached.get("AttachedPolicies", []):
                policy = iam.get_policy(PolicyArn=pol["PolicyArn"])
                version_id = policy["Policy"]["DefaultVersionId"]

                version = iam.get_policy_version(
                    PolicyArn=pol["PolicyArn"],
                    VersionId=version_id
                )

                misconfigs.extend(
                    analyze_policy_document(version["PolicyVersion"]["Document"])
                )

            inline_policies = iam.list_group_policies(GroupName=group_name)
            for pname in inline_policies.get("PolicyNames", []):
                pol = iam.get_group_policy(GroupName=group_name, PolicyName=pname)
                misconfigs.extend(analyze_policy_document(pol["PolicyDocument"]))

            findings.append(format_finding(
                resource_type="IAM Group",
                resource_id=group_name,
                details={
                    "Arn": group["Arn"],
                    "CreateDate": str(group["CreateDate"])
                },
                misconfigurations=misconfigs
            ))

    except ClientError as e:
        print_warning(f"[IAM] Group enumeration failed: {e}")

    return findings


# ---------------------------------------------------------------------------
# Enumerate IAM Roles
# ---------------------------------------------------------------------------

def enumerate_roles(iam, logger):
    findings = []

    try:
        roles = iam.list_roles().get("Roles", [])

        for role in roles:
            role_name = role["RoleName"]
            misconfigs = []

            trust_policy = role.get("AssumeRolePolicyDocument", {})
            misconfigs.extend(analyze_policy_document(trust_policy))

            attached = iam.list_attached_role_policies(RoleName=role_name)
            for pol in attached.get("AttachedPolicies", []):
                policy = iam.get_policy(PolicyArn=pol["PolicyArn"])
                version_id = policy["Policy"]["DefaultVersionId"]

                version = iam.get_policy_version(
                    PolicyArn=pol["PolicyArn"],
                    VersionId=version_id
                )

                misconfigs.extend(
                    analyze_policy_document(version["PolicyVersion"]["Document"])
                )

            inline_policies = iam.list_role_policies(RoleName=role_name)
            for pname in inline_policies.get("PolicyNames", []):
                pol = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                misconfigs.extend(analyze_policy_document(pol["PolicyDocument"]))

            findings.append(format_finding(
                resource_type="IAM Role",
                resource_id=role_name,
                details={
                    "Arn": role["Arn"],
                    "CreateDate": str(role["CreateDate"])
                },
                misconfigurations=misconfigs
            ))

    except ClientError as e:
        print_warning(f"[IAM] Role enumeration failed: {e}")

    return findings


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def enumerate_iam(session, logger, return_raw=False):
    print_info("[IAM] Starting IAM enumeration")

    iam = session.client("iam")
    findings = []

    findings.extend(enumerate_users(iam, logger))
    findings.extend(enumerate_groups(iam, logger))
    findings.extend(enumerate_roles(iam, logger))

    print_success(f"[IAM] Enumeration complete: {len(findings)} findings collected")
    return findings


# ---------------------------------------------------------------------------
# Optional Wrapper
# ---------------------------------------------------------------------------

def run_iam_enum(session, logger, return_raw=False):
    return enumerate_iam(session, logger, return_raw)
