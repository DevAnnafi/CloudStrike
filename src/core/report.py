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
                "cloud_provider": self.cloud_service
        },   

        "findings" : self.findings
    }

    def save_json(self, output):
        with open(output, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)