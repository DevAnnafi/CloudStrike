"""CloudStrike Configuration Management"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
CONFIG_DIR = BASE_DIR / "config"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# AWS
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Azure
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

# GCP
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
GCP_CREDENTIALS_PATH = os.getenv("GCP_CREDENTIALS_PATH")

# Scan
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_THREADS = int(os.getenv("MAX_THREADS", "10"))
VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"

# Reporting
REPORT_FORMAT = os.getenv("REPORT_FORMAT", "html")
REPORT_LEVEL = os.getenv("REPORT_LEVEL", "detailed")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

if __name__ == "__main__":
    print(f"Base Directory: {BASE_DIR}")
    print(f"Reports Directory: {REPORTS_DIR}")
    print(f"✅ Configuration loaded!")
