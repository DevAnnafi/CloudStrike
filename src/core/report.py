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

        "posture": { 
            "overall_score": self.get_posture_score(),
            "cloud_breakdown": self.get_cloud_breakdown()
        },

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
    
    def get_posture_score(self):
        score = 100

        for finding in self.findings:
            severity = finding["severity"]
            if severity == 'critical':
                score -= 10
            elif severity == 'high':
                score -= 5
            elif severity == 'medium':
                score -= 2
            elif severity == 'low':
                score -= 1

        return max(0, score)
    
    def get_cloud_breakdown(self):
        breakdown = {}
        for finding in self.findings:
            cloud_provider = finding['cloud_provider']
            if cloud_provider not in breakdown:
                breakdown[cloud_provider] = {
                    "findings_count" : 0,
                    "critical" : 0,
                    "high" : 0,
                    "medium" : 0,
                    "low" : 0,
                    "score" : 100
                }
            
            breakdown[cloud_provider]["findings_count"] += 1

            severity = finding['severity']
            breakdown[cloud_provider][severity] += 1

        for cloud in breakdown:
            critical = breakdown[cloud]["critical"]
            high = breakdown[cloud]["high"]
            medium = breakdown[cloud]["medium"]
            low = breakdown[cloud]["low"]
            
            score = 100 - (critical * 10) - (high * 5) - (medium * 2) - (low * 1)
            breakdown[cloud]["score"] = max(0, score)

        return breakdown

    def save_json(self, output):
        with open(output, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)