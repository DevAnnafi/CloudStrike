from azure.mgmt.authorization import AuthorizationManagementClient
from azure.identity import DefaultAzureCredential
from core.enums import CloudProvider, Severity, FindingType

class RBACAnalyzer():
    def __init__(self, subscription_id=None, account_name=None):
        self.findings = []
        self.subscription_id = subscription_id
        self.account_name = account_name or "Default"
        
        self.credential = DefaultAzureCredential()
        self.authorization_client = AuthorizationManagementClient(self.credential, subscription_id)

    def scan(self):
        try:
            assignments = self.authorization_client.role_assignments.list()
            for assignment in assignments:
                self.check_role_assignment(assignment)
        except:
            pass
        return self.findings

    def check_role_assignment(self, assignment):
        if assignment.role_definition_id.endswith("8e3af657-a8ff-443c-a75c-2fe8c4bcb635"):
            self.findings.append({
                "severity": Severity.CRITICAL.value,
                "title": "Overly Permissive Azure Role Assignment - Owner",
                "resource": assignment.principal_id,
                "cloud_provider": "Azure",
                "account_id": self.subscription_id,
                "account_name": self.account_name,
                "description": f"Principal has Owner role assigned at scope: {assignment.scope}"
            })
        
        elif assignment.role_definition_id.endswith("b24988ac-6180-42a0-ab88-20f7382dd24c"):
            self.findings.append({
                "severity": Severity.HIGH.value,
                "title": "Overly Permissive Azure Role Assignment - Contributor",
                "resource": assignment.principal_id,
                "cloud_provider": "Azure",
                "account_id": self.subscription_id,
                "account_name": self.account_name,
                "description": f"Principal has Contributor role assigned at scope: {assignment.scope}"
            })
        
        elif assignment.role_definition_id.endswith("18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"):
            self.findings.append({
                "severity": Severity.CRITICAL.value,
                "title": "Overly Permissive Azure Role Assignment - User Access Administrator",
                "resource": assignment.principal_id,
                "cloud_provider": "Azure",
                "account_id": self.subscription_id,
                "account_name": self.account_name,
                "description": f"Principal has User Access Administrator role assigned at scope: {assignment.scope}"
            })