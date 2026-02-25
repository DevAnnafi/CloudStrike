import requests
import boto3
from core.enums import Severity, CloudProvider, FindingType

class EC2MetaDataScanner():
    METADATA_ENDPOINT = "http://169.254.169.254/latest/meta-data/"
    def __init__(self, profile_name=None, account_name=None):
        self.findings = []
        self.account_name = account_name or "Default"

        try:
            session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
        except:
            self.account_id = "unknown"
    def scan(self):
        self.check_imds_version()
        return self.findings

    def check_imds_accessible(self):
        try:
            response = requests.get(self.METADATA_ENDPOINT, timeout=2)
            if response.status_code == 200:
                return True
        except:
            pass

        return False
          

    def check_imds_version(self):
        if not self.check_imds_accessible():
            return
        try:
            response = requests.get(self.METADATA_ENDPOINT)
            if response.status_code == 200:
                self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "IMDSv1 Enabled",
                    "resource" : "EC2 Instance",
                    "cloud_provider": "AWS",
                    "account_id": self.account_id,
                    "account_name": self.account_name,
                    "description" : "Instance allows IMDSv1 access, vulnerable to SSRF attacks"
                })
        except:
            pass