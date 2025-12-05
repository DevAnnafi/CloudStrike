# Import typing tools for type hints.
from typing import *

# Import the save_json function to write the final report.
from utils import save_json

# Import logger functions for printing status updates.
from logger import print_warning, print_success, print_error, print_info

# Create a class named CloudStrikeReport.

class CloudStrikeReport:

# In the constructor, initialize a list to store all findings.
    def __init__(self):
        self.findings = []

# Define a method named add_finding that accepts service name, misconfiguration title,
# severity, evidence, and recommended fix. It should append a structured dictionary
# to the findings list and log that the finding was added.
    def add_finding(self,service_name, misconfiguration_title, severity, evidence, recommended_fix):
        finding = {
            "service": service_name,
            "title": misconfiguration_title,
            "severity": severity,
            "evidence": evidence,
            "fix": recommended_fix
        }
        self.findings.append(finding)
        print_success(f"Added finding: {misconfiguration_title}")


# Define an export method that writes all collected findings to cloudstrike_report.json
# using the save_json helper function.
    def export(self):
        save_json("cloudstrike_report.json", self.findings)
        print_success("Report exported to cloudstrike_report.json")

