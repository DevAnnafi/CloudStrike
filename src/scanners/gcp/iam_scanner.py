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
        if binding.role == "roles/owner":
            self.findings.append({
                "severity": Severity.CRITICAL.value,
                "title": "Overly Permissive GCP IAM Binding - Owner",
                "resource": binding.role,
                "cloud_provider": "GCP",
                "account_id": self.project_id,
                "account_name": self.account_name,
                "description": f"Role {binding.role} grants full project control"
            })
        
        elif binding.role == "roles/editor":
            self.findings.append({
                "severity": Severity.HIGH.value,
                "title": "Overly Permissive GCP IAM Binding - Editor",
                "resource": binding.role,
                "cloud_provider": "GCP",
                "account_id": self.project_id,
                "account_name": self.account_name,
                "description": f"Role {binding.role} grants broad resource modification permissions but not IAM control"
            })
        
        if 'allUsers' in binding.members:
            self.findings.append({
                "severity": Severity.CRITICAL.value,
                "title": "Public GCP IAM Binding - Internet Access",
                "resource": binding.role,
                "cloud_provider": "GCP",
                "account_id": self.project_id,
                "account_name": self.account_name,
                "description": f"Role {binding.role} is assumable by anyone on the internet (allUsers)"
            })
        
        elif 'allAuthenticatedUsers' in binding.members:
            self.findings.append({
                "severity": Severity.HIGH.value,
                "title": "Public GCP IAM Binding - Any Google Account",
                "resource": binding.role,
                "cloud_provider": "GCP",
                "account_id": self.project_id,
                "account_name": self.account_name,
                "description": f"Role {binding.role} is assumable by any authenticated Google account (allAuthenticatedUsers)"
            })