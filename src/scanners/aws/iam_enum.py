import boto3
import json
from core.enums import Severity, CloudProvider, FindingType

class IAMScanner():
    def __init__(self, profile_name=None, account_name=None):
        self.findings = []
        self.account_name = account_name or "Default"
        
        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        self.sts_client = session.client('sts')
        self.iam_client = session.client('iam')
        
        try:
            identity = self.sts_client.get_caller_identity()
            self.account_id = identity['Account']
        except:
            self.account_id = "unknown"
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
            self.check_attach_group_policy(permissions)
            self.check_attach_role_policy(permissions)
            self.check_put_group_policy(permissions)
            self.check_put_role_policy(permissions)
            self.check_create_policy(permissions)
            self.check_create_login_profile(permissions)
            self.check_update_login_profile(permissions)
            self.check_set_default_policy_version(permissions)
            self.check_passrole_ec2(permissions)
            self.check_passrole_cloudformation(permissions)
            self.check_passrole_data_pipeline(permissions)
            self.check_passrole_glue(permissions)
            self.check_assume_role(permissions)
            self.check_lambda_invoke(permissions)
            self.check_ec2_run_instances(permissions)
            self.check_wildcard(permissions)

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
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,          
                "description" : "User has iam:CreateAccessKey permission, can create keys for other users"
            })
       
    def check_attach_user_policy(self, permissions):
        if "iam:AttachUserPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - AttachUserPolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:AttachUserPolicy permission, can attach admin policies to themselves"
            })

    def check_put_user_policy(self, permissions):
        if "iam:PutUserPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PutUserPolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PutUserPolicy permission, can create inline policies with admin privileges"
            })

    def check_passrole_lambda(self, permissions):
        if "iam:PassRole" in permissions and "lambda:CreateFunction" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title": "IAM Privilege Escalation - PassRole + Lambda",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PassRole and lambda:CreateFunction permissions, can assume privileged roles via Lambda"
            })

    def check_attach_group_policy(self, permissions):
        if "iam:AttachGroupPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - AttachGroupPolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:AttachGroupPolicy permissions, can attach admin policies to groups"
            })

    def check_attach_role_policy(self, permissions):
        if "iam:AttachRolePolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - AttachRolePolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:AttachRolePolicy permissions, can attach admin policies to roles"
            })

    def check_put_group_policy(self, permissions):
        if "iam:PutGroupPolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PutGroupPolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PutGroupPolicy permissions, can create inline policies on groups"
            })

    def check_put_role_policy(self, permissions):
        if "iam:PutRolePolicy" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PutRolePolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PutRolePolicy permissions, can create inline policies to roles"
            })

    def check_create_policy(self, permissions):
        if "iam:CreatePolicy" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - CreatePolicy",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:CreatePolicy permissions, can create new admin policies"
            })

    def check_create_login_profile(self,permissions):
        if "iam:CreateLoginProfile" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - CreateLoginProfile",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:CreateLoginProfile permissions, can create console passwords for other users"
            })
    

    def check_update_login_profile(self, permissions):
        if "iam:UpdateLoginProfile" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - UpdateLoginProfile",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:UpdateLoginProfile permissions, can change console passwords for other users"
            })

    def check_set_default_policy_version(self,permissions):
        if "iam:SetDefaultPolicyVersion" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - SetDefaultPolicyVersion",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:SetDefaultPolicyVersion permission, can revert policies to privileged versions"
            })

    def check_passrole_ec2(self,permissions):
        if "iam:PassRole" in permissions and "ec2:RunInstances" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PassRole + EC2",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PassRole and ec2:RunInstances permissions, can launch EC2 instances with privileged roles"
            })

    def check_passrole_cloudformation(self,permissions):
        if "iam:PassRole" in permissions and "cloudformation:CreateStack" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - PassRole and Cloudformation",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PassRole and cloudformation:CreateStack permissions, can create stacks with privileged roles"
            }) 

    def check_passrole_data_pipeline(self, permissions):
        if "iam:PassRole" in permissions and "datapipeline:CreatePipeline" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - PassRole and Datapipeline",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PassRole and datapipeline:CreatePipeline permissions, can create pipelines with privileged roles"
            })

    def check_passrole_glue(self, permissions):
        if "iam:PassRole" in permissions and "glue:CreateDevEndpoint" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - PassRole + Glue",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has iam:PassRole and glue:CreateDevEndpoint permissions, can create Glue endpoints with privileged roles"              
            })

    def check_assume_role(self, permissions):
        if "sts:AssumeRole" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - AssumeRole",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has sts:AssumeRole permission, can assume privileged roles"
            })
    
    def check_lambda_invoke(self, permissions):
        if "lambda:InvokeFunction" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - InvokeFunction",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has lambda:InvokeFunction permission, can invoke Lambda functions with privileged roles"
            })

    def check_ec2_run_instances(self, permissions):
        if "ec2:RunInstances" in permissions:
            self.findings.append({
                "severity" : Severity.HIGH.value,
                "title" : "IAM Privilege Escalation - RunInstances",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has ec2:RunInstances permission, can launch instances with instance profiles"          
            })

    def check_wildcard(self, permissions):
        if "iam:*" in permissions or "*:*" in permissions or "*" in permissions:
            self.findings.append({
                "severity" : Severity.CRITICAL.value,
                "title" : "IAM Privilege Escalation - Wildcard Permissions",
                "resource" : "Current User",
                "cloud_provider": "AWS",
                "account_id": self.account_id,
                "account_name": self.account_name,
                "description" : "User has wildcard permissions, grants excessive privileges"                  
            })




