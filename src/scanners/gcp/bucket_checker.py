from google.cloud import storage
from core.enums import CloudProvider, Severity, FindingType

class BucketScanner():
    def __init__(self, project_id=None, account_name=None):
        self.findings = []
        self.project_id = project_id
        self.account_name = account_name or "Default"
        
        self.storage_client = storage.Client(project=project_id)

    def scan(self):
        try:
            buckets = self.storage_client.list_buckets()
            for bucket in buckets:
                self.check_bucket_iam_policy(bucket)
        except:
            pass

        return self.findings


    def check_bucket_iam_policy(self, bucket):
        policy = bucket.get_iam_policy()
        for binding in policy.bindings:
            if 'allUsers'in binding['members']:
                self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "Public GCP Storage Bucket",
                    "resource" : bucket.name,
                    "cloud_provider": "GCP", 
                    "account_id": self.project_id,  
                    "account_name": self.account_name,
                    "description" : f"Bucket allows public access via IAM policy"
                })
                
            elif 'allAuthenticatedUsers' in binding['members']:
                self.findings.append({
                    "severity": Severity.HIGH.value,
                    "title": "Public GCP Storage Bucket - Any Google Account Access",
                    "resource": bucket.name,
                    "cloud_provider": "GCP",
                    "account_id": self.project_id,
                    "account_name": self.account_name,
                    "description": f"Bucket '{bucket.name}' allows access to any authenticated Google account via IAM policy (allAuthenticatedUsers)"
                })


            