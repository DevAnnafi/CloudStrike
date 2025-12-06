# Import required AWS SDK libraries (boto3) for EC2 enumeration operations.
# Import logging utilities so the scanner can send messages to the central logger.
# Import any shared helper functions from cloudstrike.core.utils.

# Define a class or function responsible for enumerating EC2 instances.
# This should include:
#   - Connecting to EC2 using boto3
#   - Listing instances, instance states, tags, IAM roles, and security groups
#   - Capturing metadata that may indicate misconfigurations
#   - Returning structured findings back to the main framework

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
