from google.cloud import storage
from core.enums import CloudProvider, Severity, FindingType

class BucketScanner():
    def __init__(self, project_id=None):
        self.findings = []

        self.storage_client = storage.Client(project=project_id)
        self.project_id = project_id

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
            if 'allUsers'in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "Public GCP Storage Bucket",
                    "resource" : bucket.name,
                    "description" : f"Bucket allows public access via IAM policy"
                })


            