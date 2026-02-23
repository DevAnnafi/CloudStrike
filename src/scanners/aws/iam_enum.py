import boto3
import json
from core.enums import Severity, CloudProvider, FindingType

class IAMScanner():
    def __init__(self, profile_name=None):
        self.findings = []

        if profile_name:
            session = boto3.Session(profile_name=profile_name)
            self.iam_client = session.client('iam')
            self.sts_client = session.client('sts')
        else:
            self.iam_client = boto3.client('iam')
            self.sts_client = boto3.client('sts')

    def scan(self):
        try:
            response = self.sts_client.get_caller_identity()
            arn = response["Arn"]
            username = arn.split("/")[-1]

            permissions = self.get_user_permissions(username)

            self.check_create_access_key(permissions)
            self.check_attach_user_policy(permissions)
            self.check_passrole_lambda(permissions)
            self.check_put_user_policy(permissions)

            return self.findings
    
        except Exception as e:
            print(f"Error scanning IAM: {e}")
            return self.findings
    
    def get_user_permissions(self,username):
        permissions = []

        try:
            response = self.iam_client.list_attached_user_policies(UserName=username)
            attached_policies = response["AttachedPolicies"]
            for policy in attached_policies:
                policy_arn = policy["PolicyArn"]
                policy_details = self.iam_client.get_policy(PolicyArn=policy_arn)
                version_id = policy_details['Policy']['DefaultVersionId']
                policy_document = self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                document = policy_document["PolicyVersion"]['Document']
                for statement in document['Statement']:
                    if statement["Effect"] == 'Allow':
                        action = statement['Action']
                        if isinstance(action, list):
                            permissions.extend(action)
                        else:
                            permissions.append(action)
        except:
            return permissions
    
        return permissions
    def check_create_access_key(self, permissions):
        if "iam:CreateAccessKey" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - CreateAccessKey",
                "resource" : "Current User",
                "description" : "User has iam:CreateAccessKey permission, can create keys for other users"
            })
       
    def check_attach_user_policy(self, permissions):
        if "iam:AttachUserPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - AttachUserPolicy",
                "resource" : "Current User",
                "description" : "User has iam:AttachUserPolicy permission, can attach admin policies to themselves"
            })

    def check_put_user_policy(self, permissions):
        if "iam:PutUserPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PutUserPolicy",
                "resource" : "Current User",
                "description" : "User has iam:PutUserPolicy permission, can create inline policies with admin privileges"
            })

    def check_passrole_lambda(self, permissions):
        if "iam:PassRole" in permissions and "lambda:CreateFunction" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title": "IAM Privilege Escalation - PassRole + Lambda",
                "resource" : "Current User",
                "description" : "User has iam:PassRole and lambda:CreateFunction permissions, can assume privileged roles via Lambda"
            })




