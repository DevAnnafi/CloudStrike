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

# Return results as a dictionary or list of findings so they can be
# added directly into the JSON report.

# At the bottom, optionally define a convenience function such as:
#   - run_ec2_enum()
# that can be called by the CLI module.
