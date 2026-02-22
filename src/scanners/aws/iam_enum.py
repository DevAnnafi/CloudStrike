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
        pass
       
    def check_attach_user_policy(self):
        pass

    def check_put_user_policy(self):
        pass

    def check_passrole_lambda(self):
        pass




