"""
Global configuration manager for CloudStrike.
Lives in: cloudstrike/config/settings.py

Handles:
- Loading configuration files
- Providing default settings
- Merging user overrides
"""

import os
import yaml

# ---------------------------------------------------
# PATHS
# ---------------------------------------------------
# Because this file is already inside /config, we load
# cloudstrike.yaml from the SAME directory.
CONFIG_DIR = os.path.dirname(__file__)
DEFAULT_CONFIG_FILE = os.path.join(CONFIG_DIR, "cloudstrike.yaml")


# ---------------------------------------------------
# Load the YAML config file
# ---------------------------------------------------
def load_config(path: str = DEFAULT_CONFIG_FILE) -> dict:
    """
    Loads cloudstrike.yaml from the /config directory.

    Returns {} if the file doesn't exist.
    """
    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------
# DEFAULT SETTINGS
# ---------------------------------------------------
DEFAULT_SETTINGS = {
    "log_level": "INFO",
    "threads": 4,
    "output_file": "cloudstrike_report.json",

    "aws": {
        "enable_s3": True,
        "enable_iam": True,
        "enable_metadata": True,
    },

    "azure": {
        "enable_storage": True,
        "enable_iam": True,
        "enable_metadata": True,
    },

    "gcp": {
        "enable_storage": True,
        "enable_iam": True,
        "enable_metadata": True,
    },
}


# ---------------------------------------------------
# Merge user overrides with defaults
# ---------------------------------------------------
def load_settings() -> dict:
    """
    Loads DEFAULT_SETTINGS and overrides them with any
    values found in cloudstrike.yaml.
    """
    user_config = load_config()
    settings = DEFAULT_SETTINGS.copy()

    # Deep-merge nested dictionaries (AWS, Azure, GCP)
    for key, value in user_config.items():
        if isinstance(value, dict) and key in settings:
            settings[key].update(value)
        else:
            settings[key] = value

    return settings
