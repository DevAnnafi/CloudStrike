from azure.mgmt.authorization import AuthorizationManagementClient
from azure.identity import DefaultAzureCredential
from core.enums import CloudProvider, Severity, FindingType

class RBACAnalyzer():
    def __init__(self, subscription_id=None):
        self.findings = []

        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.authorization_client = AuthorizationManagementClient(self.credential, self.subscription_id)

    def scan(self):
        try:
            assignments = self.authorization_client.role_assignments.list()
            for assignment in assignments:
                self.check_role_assignment(assignment)
        except:
            pass
        return self.findings

    def check_role_assignment(self, assignment):
        dangerous_roles = [
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            "b24988ac-6180-42a0-ab88-20f7382dd24c",
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
        ]

        for role_guid in dangerous_roles:
            if assignment.role_definition_id.endswith(role_guid):
                self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "Overly Permissive Azure Role Assignment",
                    "resource" : assignment.principal_id,
                    "description" : f"Principal has {role_guid} role assigned at scope: {assignment.scope}"
                })