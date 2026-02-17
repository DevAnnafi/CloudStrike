from datetime import datetime
import json

class ReportGenerator:

    def __init__(self, findings, cloud_service):
        self.findings = findings
        self.cloud_service = cloud_service
        

    def to_dict(self):
        return {
            "metadata": {
                "tool": "CloudStrike",
                "timestamp" : datetime.utcnow().isoformat(),
                "cloud_provider": self.cloud_service,
        }, 
        "summary" : self.get_summary(),

        "findings" : self.findings
    }

    def get_summary(self):
       total = len(self.findings)
       critical = len([f for f in self.findings if f["severity"] == "critical"])
       high = len([f for f in self.findings if f["severity"] == "high"])
       medium = len([f for f in self.findings if f["severity"] == "medium"])
       low = len([f for f in self.findings if f["severity"] == "low"])
       return {
            "total" : total,
            "critical" : critical,
            "high" : high,
            "medium" : medium,
            "low" : low
        }


    def save_json(self, output):
        with open(output, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)