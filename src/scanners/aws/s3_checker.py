import boto3
import json
from core.enums import Severity, CloudProvider, FindingType

class S3Scanner():  
    def __init__(self, profile_name=None, account_name=None):
        self.findings = []
        self.account_name = account_name or "Default"
        
        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        self.s3_client = session.client('s3')
        
        sts_client = session.client('sts')
        try:
            identity = sts_client.get_caller_identity()
            self.account_id = identity['Account']
        except:
            self.account_id = "unknown"


    def scan_buckets(self):
        try:
            response = self.s3_client.list_buckets()
            buckets = response['Buckets']
            for bucket in buckets:
                bucket_name = bucket["Name"]
                self.check_public_access(bucket_name)
                self.check_acl(bucket_name)
                self.check_policy(bucket_name)
                self.check_encryption(bucket_name)
        except:
            pass

        return self.findings

    def check_public_access(self, bucket_name):
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            if not all([config['BlockPublicAcls'], 
                        config['IgnorePublicAcls'],
                        config['BlockPublicPolicy'],
                        config['RestrictPublicBuckets']]):
                self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "S3 Bucket Not Protected",
                    "resource" : bucket_name,
                    "cloud_provider": "AWS",              
                    "account_id": self.account_id,        
                    "account_name": self.account_name,    
                    "description" : "Block Public Access settings are not fully enabled"
                })
        except:
            self.findings.append({
                    "severity" : Severity.CRITICAL.value,
                    "title" : "S3 Bucket Not Protected",
                    "resource" : bucket_name,
                    "cloud_provider": "AWS",              
                    "account_id": self.account_id,        
                    "account_name": self.account_name, 
                    "description" : "Block Public Access settings are not fully enabled"
                })

    def check_acl(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = response['Grants']

            for grant in grants:
                if 'URI' in grant.get('Grantee', {}):
                    uri = grant['Grantee']['URI']
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        self.findings.append({
                            "severity" : Severity.CRITICAL.value,
                            "title" : "Public S3 Bucket via ACL",
                            "resource" : bucket_name,
                            "cloud_provider": "AWS",              
                            "account_id": self.account_id,        
                            "account_name": self.account_name, 
                            "description" : "Bucket ACL grants public access"
                        })
        except: 
              pass

    def check_policy(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response["Policy"])
            statements = policy["Statement"]
            for statement in statements:
                if statement["Effect"] == 'Allow' and (statement['Principal'] == '*' or statement['Principal'] == {'AWS': '*'}):
                    self.findings.append({
                        "severity" : Severity.CRITICAL.value,
                        "title" : "Public S3 Bucket via Policy",
                        "resource" : bucket_name,
                        "cloud_provider": "AWS",              
                        "account_id": self.account_id,        
                        "account_name": self.account_name, 
                        "description" : "Bucket policy grants public access"
                    })
        except:
            pass

    def check_encryption(self, bucket_name):
        try:
             self.s3_client.get_bucket_encryption(Bucket=bucket_name)
        except:
            self.findings.append({
                "severity" : Severity.MEDIUM.value,
                "title" : "S3 Bucket Encryption Disabled",
                "resource" : bucket_name,
                "cloud_provider": "AWS",              
                "account_id": self.account_id,        
                "account_name": self.account_name, 
                "description": "Bucket does not have default encryption enabled"
            })

    
        

