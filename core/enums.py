# Import Enum from the enum module to create typed enumerations.
from enum import Enum

# Define an enumeration for severity levels (e.g., LOW, MEDIUM, HIGH, CRITICAL).
# These will be used across all modules to standardize severity scoring.
class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# Define an enumeration for cloud providers (AWS, AZURE, GCP).
# This helps categorize findings and improves consistency in the report.
class Cloud_Providers(Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"

# Define an enumeration for service categories if needed (STORAGE, IAM, COMPUTE, NETWORK).
# These can help organize findings into broader groups.
class Services(Enum):
    STORAGE = "STORAGE"
    IAM = "IAM"
    COMPUTE = "COMPUTE"
    NETWORK = "NETWORK"

# Optionally define an enumeration for scan status (SUCCESS, FAILED, SKIPPED).
# Useful for diagnostic output or CI integration.
class Status(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"

