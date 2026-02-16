from enum import Enum

class CloudProvider(Enum):
    AWS = 'aws'
    AZURE = 'azure'
    GCP = 'gcp'

    def __str__(self):
        return self.value
    
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __repr__(self):
        return self.value
    
    @classmethod
    def from_score(cls, score: int):
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO
        
class FindingType(Enum):
    # Storage
    PUBLIC_BUCKET = 'public_bucket'
    UNENCRYPTED_STORAGE = 'unencrypted_storage'

    # IAM & Access
    IAM_MISCONFIGURATION = "iam_misconfiguration"
    OVERPRIVILEGED_ROLE = "overprivileged_role"
    EXPOSED_CREDENTIALS = "exposed_credentials"
    MFA_DISABLED = "mfa_disabled"
    
    # Network
    OPEN_SECURITY_GROUP = "open_security_group"
    PUBLIC_DATABASE = "public_database"
    UNRESTRICTED_INGRESS = "unrestricted_ingress"
    
    # Encryption
    MISSING_ENCRYPTION = "missing_encryption"
    WEAK_ENCRYPTION = "weak_encryption"
    
    # Compliance
    LOGGING_DISABLED = "logging_disabled"
    MONITORING_DISABLED = "monitoring_disabled"
    COMPLIANCE_VIOLATION = "compliance_violation"
    
    def __str__(self):
        return self.value