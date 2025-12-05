# Import Enum from the enum module to create typed enumerations.

# Define an enumeration for severity levels (e.g., LOW, MEDIUM, HIGH, CRITICAL).
# These will be used across all modules to standardize severity scoring.

# Define an enumeration for cloud providers (AWS, AZURE, GCP).
# This helps categorize findings and improves consistency in the report.

# Define an enumeration for service categories if needed (STORAGE, IAM, COMPUTE, NETWORK).
# These can help organize findings into broader groups.

# Optionally define an enumeration for scan status (SUCCESS, FAILED, SKIPPED).
# Useful for diagnostic output or CI integration.

# Add docstrings explaining that enums enforce consistency and prevent typos
# in repeated string values across the framework.
