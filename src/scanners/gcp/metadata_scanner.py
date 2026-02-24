import requests
from core.enums import Severity, CloudProvider, FindingType

class MetaDataScanner():
    METADATA_ENDPOINT = "http://metadata.google.internal/computeMetadata/v1/"
    def __init__(self):
        self.findings = []

    def scan(self):
        self.check_imds_version()
        return self.findings

    def check_imds_version(self):
        if not self.check_imds_accessible():
            return  
        self.findings.append({
            "severity" : Severity.CRITICAL.value,
            "title" : "GCP IMDS Accessible",
            "resource" : "GCP Instance",
            "description" : "Instance Metadata Service is accessible, metadata service is at a security risk"
        })

    def check_imds_accessible(self):
        try:
            header = {
                "Metadata-Flavor" : "Google"
            }
            response = requests.get(self.METADATA_ENDPOINT, headers=header, timeout=2)
            if response.status_code == 200:
                return True           
        except:
            pass

        return False