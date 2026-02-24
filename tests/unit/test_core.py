import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

import pytest
from datetime import datetime
from core.report import ReportGenerator
from core.utils import format_timestamp_human, format_timestamp_filename, ensure_directory_exists, validate_output_path

findings = [
    {"severity": "critical", "title": "Public S3 Bucket", "cloud": "AWS"},
    {"severity": "high", "title": "IAM Misconfiguration", "cloud": "AWS"},
    {"severity": "high", "title": "Open Security Group", "cloud": "AWS"},
    {"severity": "medium", "title": "Unencrypted Volume", "cloud": "AWS"},
]

def test_to_dict():
    report = ReportGenerator(findings, "AWS")
    result = report.to_dict()
    assert "metadata" in result
    assert "summary" in result
    assert "findings" in result

def test_get_summary():
    report = ReportGenerator(findings, "AWS")
    result = report.to_dict()
    assert result["summary"]["critical"] == 1
    assert result["summary"]["high"] == 2
    assert result["summary"]["medium"] == 1
    assert result["summary"]["low"] == 0

def test_save_json():
    report = ReportGenerator(findings, "AWS")
    report.save_json("test_output.json")
    assert Path("test_output.json").exists()

def test_format_timestamp_human():
    current_date = datetime.now()
    result = format_timestamp_human(current_date)
    assert isinstance(result, str)

def test_format_timestamp_filename():
    current_date = datetime.now()
    result = format_timestamp_filename(current_date)
    assert isinstance(result, str)

def test_validate_output_path():
    assert validate_output_path("report.json") == True
    assert validate_output_path("report.txt") == False