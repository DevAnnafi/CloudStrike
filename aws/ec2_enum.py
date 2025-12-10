# Import required AWS SDK libraries (boto3) for EC2 enumeration operations.
# Import logging utilities so the scanner can send messages to the central logger.
# Import any shared helper functions from cloudstrike.core.utils.

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from core.logger import print_info, print_warning, print_error, print_success
from core.utils import safe_execute, format_finding
import requests

import botocore

def enumerate_ec2_instance(session, logger, region, filters=None, return_raw=False):
    """
    Enumerate EC2 instances across one or multiple regions and return
    normalized CloudStrike-ready findings.
    """

    findings = []

    # Support a single region (string) or a list of regions
    regions = [region] if isinstance(region, str) else region

    for rg in regions:
        try:
            # Connect to EC2 in requested region
            ec2 = session.resource("ec2", region_name=rg)

            # Fetch EC2 instances
            if filters:
                instances = ec2.instances.filter(Filters=filters)
            else:
                instances = ec2.instances.all()

            for instance in instances:

                # Optionally return raw boto3 objects
                if return_raw:
                    findings.append(instance)
                    continue

                # Convert tags into dict
                tag_dict = {t["Key"]: t["Value"] for t in instance.tags} if instance.tags else {}

                # -------------------------------
                # Basic Misconfiguration Detection
                # -------------------------------
                misconfigs = []

                if instance.public_ip_address:
                    misconfigs.append("Public IP Assigned")

                if not instance.security_groups:
                    misconfigs.append("No Security Groups Attached")

                if not getattr(instance, "iam_instance_profile", None):
                    misconfigs.append("No IAM Instance Profile")

                # -------------------------------
                # Normalized CloudStrike Finding
                # -------------------------------
                instance_data = {
                    "ResourceType": "EC2 Instance",
                    "Region": rg,
                    "InstanceId": instance.instance_id,
                    "InstanceType": instance.instance_type,
                    "State": instance.state.get("Name"),
                    "PrivateIpAddress": instance.private_ip_address,
                    "PublicIpAddress": instance.public_ip_address,
                    "LaunchTime": str(instance.launch_time),
                    "IAMInstanceProfile": getattr(instance, "iam_instance_profile", None),
                    "SecurityGroups": [
                        {"GroupId": sg["GroupId"], "GroupName": sg["GroupName"]}
                        for sg in instance.security_groups
                    ],
                    "Tags": tag_dict,
                    "Misconfigurations": misconfigs
                }

                findings.append(instance_data)

        # ----------------------------------
        # Exception Handling
        # ----------------------------------
        except botocore.exceptions.ClientError as ce:
            error_code = ce.response["Error"]["Code"]

            if error_code in ["UnauthorizedOperation", "AccessDenied", "AccessDeniedException"]:
                logger.warning(f"[EC2] Access denied in region {rg}. Missing IAM permissions.")
            elif error_code in ["InvalidRegion", "OptInRequired"]:
                logger.warning(f"[EC2] Region {rg} is disabled or requires opt-in.")
            else:
                logger.error(f"[EC2] Client error in {rg}: {str(ce)}")

        except botocore.exceptions.EndpointConnectionError:
            logger.error(f"[EC2] Unable to connect to region {rg}. Possibly invalid or offline.")

        except Exception as e:
            logger.error(f"[EC2] Enumeration failed in region {rg}: {str(e)}")

    return findings

# Add a function or method that detects insecure configurations, such as:
#   - Publicly exposed EC2 instances
#   - Instances using outdated or deprecated AMIs
#   - Instances missing IMDSv2 enforcement
#   - Instances attached to overly permissive IAM roles
def insecure_configurations(instance, session, logger):
    misconfig = []

    # Determine correct region based on instance placement
    region = instance.placement["AvailabilityZone"][:-1]  # 'us-east-1a' -> 'us-east-1'

    ec2 = session.client("ec2", region_name=region)
    iam = session.client("iam")

    # ---------------------------------------------------------------------
    # 1. Public Exposure
    # ---------------------------------------------------------------------
    if instance.public_ip_address:
        misconfig.append("Public Exposure: Instance has a public IPv4 address.")

    # ---------------------------------------------------------------------
    # 2. Deprecated / Outdated AMI
    # ---------------------------------------------------------------------
    try:
        ami_data = ec2.describe_images(ImageIds=[instance.image_id])
        images = ami_data.get("Images", [])

        if images:
            ami = images[0]

            # Deprecation marker
            if ami.get("DeprecationTime"):
                misconfig.append(
                    f"Deprecated AMI: {instance.image_id} is deprecated as of {ami['DeprecationTime']}"
                )

            # Outdated AMI (>900 days)
            if "CreationDate" in ami:
                from datetime import datetime, timedelta
                created = datetime.fromisoformat(ami["CreationDate"].replace("Z", "+00:00"))
                if created < datetime.now(created.tzinfo) - timedelta(days=900):
                    misconfig.append(f"Outdated AMI: Created on {ami['CreationDate']}")
        else:
            misconfig.append("AMI Lookup Failed: AMI not found.")

    except Exception as e:
        logger.warning(f"[EC2] Failed to inspect AMI for {instance.id}: {e}")

    # ---------------------------------------------------------------------
    # 3. IMDSv2 Enforcement
    # ---------------------------------------------------------------------
    try:
        md = ec2.describe_instance_attribute(
            InstanceId=instance.id,
            Attribute="metadataOptions"
        )
        metadata = md.get("MetadataOptions", {})

        if metadata.get("HttpTokens") != "required":
            misconfig.append("IMDSv2 Not Enforced: HttpTokens not set to 'required'.")

    except Exception as e:
        logger.warning(f"[EC2] Metadata inspection failed for {instance.id}: {e}")

    # ---------------------------------------------------------------------
    # 4. IAM Role (permissions)
    # ---------------------------------------------------------------------
    profile = getattr(instance, "iam_instance_profile", None)

    if not profile:
        misconfig.append("IAM Role Missing: No IAM instance profile attached.")
        return misconfig

    try:
        profile_name = profile["Arn"].split("/")[-1]
        ip = iam.get_instance_profile(InstanceProfileName=profile_name)
        roles = ip["InstanceProfile"].get("Roles", [])

        for role in roles:
            role_name = role["RoleName"]

            # Managed policies
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for p in attached:
                if p["PolicyName"] == "AdministratorAccess":
                    misconfig.append(
                        f"Permissive IAM Role: {role_name} has AdministratorAccess policy attached."
                    )

            # Inline policies
            inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            for pname in inline_names:
                pol = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]

                for stmt in pol.get("Statement", []):
                    if stmt.get("Effect") == "Allow":

                        # "*" Actions
                        actions = stmt.get("Action")
                        if actions == "*" or (isinstance(actions, list) and "*" in actions):
                            misconfig.append(
                                f"Permissive Inline Policy: {pname} in {role_name} allows '*' actions."
                            )

                        # "*" Resources
                        resources = stmt.get("Resource")
                        if resources == "*" or (isinstance(resources, list) and "*" in resources):
                            misconfig.append(
                                f"Permissive Inline Policy: {pname} in {role_name} uses '*' resources."
                            )

    except Exception as e:
        logger.warning(f"[EC2] IAM inspection failed for instance {instance.id}: {e}")

    return misconfig



# Return results as a dictionary or list of findings so they can be
# added directly into the JSON report.
    misconfigs = insecure_configurations(
        instance=instance,
        session=session,
        logger=logger
    )

    instance_data = {
        "ResourceType": "EC2 Instance",
        "Region": rg,
        "InstanceId": instance.instance_id,
        "InstanceType": instance.instance_type,
        "State": instance.state.get("Name"),
        "PrivateIpAddress": instance.private_ip_address,
        "PublicIpAddress": instance.public_ip_address,
        "LaunchTime": str(instance.launch_time),
        "IAMInstanceProfile": getattr(instance, "iam_instance_profile", None),
        "SecurityGroups": [
            {"GroupId": sg["GroupId"], "GroupName": sg["GroupName"]}
            for sg in instance.security_groups
        ],
        "Tags": tag_dict,
        "Misconfigurations": misconfigs
    }

    findings.append(instance_data)


# At the bottom, optionally define a convenience function such as:
#   - run_ec2_enum()
# that can be called by the CLI module.
def run_ec2_enum(session, logger, regions=None, filters=None, return_raw=False):
    """
    Convenience wrapper that triggers EC2 enumeration with the common
    parameters used by the CLI module.

    Args:
        session: Boto3 session object.
        logger: Logger object for standardized output.
        regions: String region (e.g., "us-east-1") or list of regions.
        filters: Optional EC2 filters to apply during enumeration.
        return_raw: If True, return raw boto3 instance objects.

    Returns:
        List of normalized CloudStrike findings.
    """

    # Default to us-east-1 if no region list provided
    if regions is None:
        regions = ["us-east-1"]

    logger.info(f"[EC2] Starting enumeration for regions: {regions}")

    results = enumerate_ec2_instance(
        session=session,
        logger=logger,
        region=regions,
        filters=filters,
        return_raw=return_raw
    )

    logger.info(f"[EC2] Enumeration complete. {len(results)} findings collected.")
    return results

