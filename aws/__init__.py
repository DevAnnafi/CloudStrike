# This file marks the AWS directory as a Python package.
# It allows CloudStrike to import modules such as:
#   - s3_checker
#   - iam_enum
#   - metadata
#   - ec2_enum
#
# You can also use this file to:
#   - Expose a clean import interface for AWS modules
#   - Register available AWS scanners
#   - Handle any shared AWS initialization logic
#
# For now, this file will remain mostly empty except for
# optional import statements if you want framework-wide access.

from . import ec2_enum
from . import iam_enum
from . import metadata
from . import s3_checker

__all__ = [
    "s3_checker",
    "iam_enum",
    "metadata",
    "ec2_enum",
]