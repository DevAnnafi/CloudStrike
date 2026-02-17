import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.report import ReportGenerator

# Fake findings to test with
findings = [
    {"severity": "critical", "title": "Public S3 Bucket", "cloud": "AWS"},
    {"severity": "high", "title": "IAM Misconfiguration", "cloud": "AWS"},
    {"severity": "high", "title": "Open Security Group", "cloud": "AWS"},
    {"severity": "medium", "title": "Unencrypted Volume", "cloud": "AWS"},
]

report = ReportGenerator(findings, "AWS")

# Test to_dict
print(report.to_dict())

# Test save_json
report.save_json("test_output.json")
print("JSON saved successfully!")