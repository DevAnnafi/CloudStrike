# Import required AWS SDK libraries (boto3) for EC2 enumeration operations.
# Import logging utilities so the scanner can send messages to the central logger.
# Import any shared helper functions from cloudstrike.core.utils.

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from core.logger import print_info, print_warning, print_error, print_success
from core.utils import safe_execute, format_finding
import requests

# Define a class or function responsible for enumerating EC2 instances.
# This should include:
#   - Connecting to EC2 using boto3
#   - Listing instances, instance states, tags, IAM roles, and security groups
#   - Capturing metadata that may indicate misconfigurations
#   - Returning structured findings back to the main framework

def enumerate_ec2_instance(session, logger, region, filters=None, return_raw=False):
    findings = []
    try:
        ec2 = session.resource("ec2", region_name="us-east-1")
        
        if filters:
            instances = ec2.instances.filter(Filters=filters)
        else:
            instances = ec2.instances.all()

        for instance in instances:
            if return_raw:
                findings.append(instance)
                continue

            # Convert tags to dict format
            tag_dict = {t["Key"]: t["Value"] for t in instance.tags} if instance.tags else {}

            # Build structured finding
            instance_data = {
                "InstanceId": instance.instance_id,
                "InstanceType": instance.instance_type,
                "State": instance.state.get("Name"),
                "PrivateIpAddress": instance.private_ip_address,
                "PublicIpAddress": instance.public_ip_address,
                "LaunchTime": str(instance.launch_time),
                "IAMInstanceProfile": getattr(instance, "iam_instance_profile", None),
                "SecurityGroups": [{"GroupId": sg["GroupId"], "GroupName": sg["GroupName"]}
                                   for sg in instance.security_groups],
                "Tags": tag_dict
            }

            findings.append(instance_data)

    except Exception as e:
        logger.error(f"[EC2] Enumeration failed in region {region}: {str(e)}")

    return findings
   


# Inside the enumeration logic, make sure to:
#   - Handle exceptions such as missing permissions or region errors
#   - Support scanning multiple regions (optional but recommended)
#   - Normalize output so it fits the report structure used by CloudStrike

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
