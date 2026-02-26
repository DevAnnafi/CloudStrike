import pytest
from core.report import ReportGenerator

# Update fixtures to include v2.0 required fields
findings = [
    {
        "severity": "critical",
        "title": "Public S3 Bucket",
        "resource": "my-bucket",
        "cloud_provider": "AWS",
        "account_id": "123456789012",
        "account_name": "Test Account",
        "description": "Bucket is publicly accessible"
    },
    {
        "severity": "high",
        "title": "Missing Encryption",
        "resource": "another-bucket",
        "cloud_provider": "AWS",
        "account_id": "123456789012",
        "account_name": "Test Account",
        "description": "Bucket encryption not enabled"
    }
]

def test_to_dict():
    report = ReportGenerator(findings, "AWS")
    result = report.to_dict()
    
    assert "metadata" in result
    assert "summary" in result
    assert "posture" in result
    assert "findings" in result
    assert result["metadata"]["cloud_provider"] == "AWS"

def test_get_summary():
    report = ReportGenerator(findings, "AWS")
    result = report.to_dict()
    summary = result["summary"]
    
    assert summary["total"] == 2
    assert summary["critical"] == 1
    assert summary["high"] == 1

def test_save_json():
    report = ReportGenerator(findings, "AWS")
    report.save_json("test_output.json")
    
    import os
    assert os.path.exists("test_output.json")
    os.remove("test_output.json")