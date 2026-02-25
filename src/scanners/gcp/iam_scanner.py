from google.cloud import resourcemanager_v3
from core.enums import CloudProvider, Severity, FindingType

class IAMScanner():
    def __init__(self, project_id=None, account_name=None):
        self.findings = []
        self.project_id = project_id
        self.account_name = account_name or "Default"
        
        self.projects_client = resourcemanager_v3.ProjectsClient()

    def scan(self):
        try:
            request = resourcemanager_v3.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
            policy = self.projects_client.get_iam_policy(request=request)

            for binding in policy.bindings:
                self.check_binding(binding)
        except:
            pass

        return self.findings


    def check_binding(self, binding):
        if binding.role == "roles/owner" or binding.role == "roles/editor":
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "Overly Permissive GCP IAM Binding",
                "resource" : binding.role,
                "cloud_provider": "GCP", 
                "account_id": self.project_id,  
                "account_name": self.account_name,
                "description" : f"Role {binding.role} grants excessive permissions"
            })

        if 'allUsers' in binding.members or 'allAuthenticatedUsers' in binding.members:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "Overly Permissive GCP IAM Binding",
                "resource" : binding.role,
                "cloud_provider": "GCP", 
                "account_id": self.project_id,  
                "account_name": self.account_name,
                "description" : "Role allows public access"
            })