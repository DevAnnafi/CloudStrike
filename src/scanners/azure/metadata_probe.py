import requests
from core.enums import Severity, CloudProvider, FindingType

class MetaDataProbe():
    METADATA_ENDPOINT = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    def __init__(self, account_name=None):
        self.findings = []
        self.account_name = account_name or "Default"
        self.subscription_id = "N/A"  

    def scan(self):
        self.check_imds_version()
        return self.findings


    def check_imds_version(self):     
        if not self.check_imds_accessible():
            return  
        self.findings.append({
            "severity" : Severity.CRITICAL.value,
            "title" : "Azure IMDS Accesible",
            "resource" : "Azure VM Instance",
            "cloud_provider": "Azure",  
            "account_id": self.subscription_id,  
            "account_name": self.account_name,
            "description" : "Instance Metadata Service is accessible, potential SSRF attack"
        })



    def check_imds_accessible(self):
        try:
            header = {
                "Metadata" : "true"
            }
            response = requests.get(self.METADATA_ENDPOINT, headers=header, timeout=2)
            if response.status_code == 200:
                return True           
        except:
            pass

        return False

