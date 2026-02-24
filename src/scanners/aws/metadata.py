import requests
from core.enums import Severity, CloudProvider, FindingType

class EC2MetaDataScanner():
    METADATA_ENDPOINT = "http://169.254.169.254/latest/meta-data/"
    def __init__(self):
        self.findings = []

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
                    "description" : "Instance allows IMDSv1 access, vulnerable to SSRF attacks"
                })
        except:
            pass