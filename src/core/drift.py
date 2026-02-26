class DriftDetector:
    def __init__(self, baseline_report, current_report):
        self.baseline = baseline_report
        self.current = current_report
    
    def detect_drift(self):
        baseline_findings = self.baseline.get('findings', [])
        current_findings = self.current.get('findings', [])
        
        baseline_keys = {self._get_finding_key(f) for f in baseline_findings}
        current_keys = {self._get_finding_key(f) for f in current_findings}
        
        new_keys = current_keys - baseline_keys
        resolved_keys = baseline_keys - current_keys
        
        new_findings = [f for f in current_findings if self._get_finding_key(f) in new_keys]
        resolved_findings = [f for f in baseline_findings if self._get_finding_key(f) in resolved_keys]
        
        baseline_score = self.baseline.get('posture', {}).get('overall_score', 0)
        current_score = self.current.get('posture', {}).get('overall_score', 0)
        score_change = current_score - baseline_score
        
        if score_change > 0:
            trend = "improved"
        elif score_change < 0:
            trend = "worse"
        else:
            trend = "unchanged"
        
        return {
            "baseline_timestamp": self.baseline.get('metadata', {}).get('timestamp'),
            "current_timestamp": self.current.get('metadata', {}).get('timestamp'),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "score_change": score_change,
            "score_trend": trend,
            "baseline_score": baseline_score,
            "current_score": current_score,
            "new": new_findings,
            "resolved": resolved_findings
        }
    
    def _get_finding_key(self, finding):
        cloud = finding.get('cloud_provider', 'unknown')
        resource = finding.get('resource', 'unknown')
        title = finding.get('title', 'unknown')
        return f"{cloud}:{resource}:{title}"