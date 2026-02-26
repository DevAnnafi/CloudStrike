# CloudSecure v2.0 🛡️

**Enterprise-grade multi-cloud security scanner with posture telemetry and drift detection**

[![CI/CD](https://github.com/DevAnnafi/CloudSecure/actions/workflows/ci.yml/badge.svg)](https://github.com/DevAnnafi/CloudSecure/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CloudSecure is a comprehensive security scanning tool that identifies misconfigurations and vulnerabilities across AWS, Azure, and Google Cloud Platform. Built for security teams, DevOps engineers, and compliance auditors.

---

## Features

### Multi-Cloud Coverage
- **AWS**: S3 buckets, IAM privilege escalation (18 vectors), EC2 metadata (IMDSv1)
- **Azure**: Storage containers, RBAC roles, VM metadata
- **GCP**: Cloud Storage buckets, IAM bindings, Compute metadata

### Multi-Account Scanning
- Scan multiple AWS accounts, Azure subscriptions, and GCP projects simultaneously
- Environment-based configuration (production, staging, development)
- Consolidated reporting across all cloud accounts

### Security Posture Telemetry
- **Risk Scoring**: 0-100 security health score
- **Per-Cloud Breakdown**: Individual scores for AWS, Azure, GCP
- **Trend Analysis**: Track security improvements over time
- **Compliance Metrics**: Monitor critical, high, medium, low findings

### Drift Detection
- Compare current scan against baseline
- Identify new vulnerabilities discovered
- Track resolved security issues
- Monitor security posture trends (improved/worse/unchanged)

### 30+ Security Checks
**Critical Findings:**
- Public cloud storage (S3, Azure Blob, GCS)
- IAM privilege escalation paths
- SSRF vulnerabilities (IMDSv1 enabled)
- Wildcard permissions

**High-Risk Findings:**
- Missing encryption at rest
- Overly permissive roles (Contributor, Editor)
- Public authenticated access

---

## Quick Start

### Prerequisites
- Python 3.8+
- AWS CLI (for AWS scanning)
- Azure CLI (for Azure scanning)
- Google Cloud SDK (for GCP scanning)

### Installation
```bash
git clone https://github.com/YOUR_USERNAME/CloudSecure.git
cd CloudSecure
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Single Account Scan

**Scan AWS:**
```bash
python src/cli.py scan --aws --output aws-report.json --verbose
```

**Scan Azure:**
```bash
az login
python src/cli.py scan --azure --output azure-report.json --verbose
```

**Scan GCP:**
```bash
gcloud auth application-default login
python src/cli.py scan --gcp --output gcp-report.json --verbose
```

**Scan All Clouds:**
```bash
python src/cli.py scan --all --output multi-cloud-report.json --verbose
```

---

## Multi-Account Scanning (v2.0)

### Step 1: Create Configuration

Create `config/environments.yml`:
```yaml
production:
  aws:
    - profile: prod-main
      name: "Production Main Account"
    - profile: prod-dr
      name: "Production DR Account"
  azure:
    - subscription_id: "12345678-1234-1234-1234-123456789012"
      name: "Production Subscription"
  gcp:
    - project_id: "my-prod-project-123"
      name: "Production GCP Project"

staging:
  aws:
    - profile: staging
      name: "Staging Account"
  azure:
    - subscription_id: "87654321-4321-4321-4321-210987654321"
      name: "Staging Subscription"
```

### Step 2: Configure Credentials

**AWS** (`~/.aws/credentials`):
```ini
[prod-main]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET

[prod-dr]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET
```

**Azure**:
```bash
az login
az account list --output table
```

**GCP**:
```bash
gcloud auth application-default login
gcloud config set project my-prod-project-123
```

### Step 3: Run Multi-Account Scan
```bash
python src/cli.py scan \
  --environment production \
  --config config/environments.yml \
  --output production-report.json \
  --verbose
```

---

## Drift Detection

Track security changes over time:
```bash
# Create baseline
python src/cli.py scan \
  --environment production \
  --config config/environments.yml \
  --output baseline.json

# Compare against baseline
python src/cli.py scan \
  --environment production \
  --config config/environments.yml \
  --baseline baseline.json \
  --output current.json
```

The report will include drift analysis:
```json
{
  "drift": {
    "baseline_timestamp": "2026-02-25T20:00:00",
    "current_timestamp": "2026-02-26T02:00:00",
    "new_findings": 3,
    "resolved_findings": 1,
    "score_change": -15,
    "score_trend": "worse",
    "baseline_score": 85,
    "current_score": 70,
    "new": [...],
    "resolved": [...]
  }
}
```

---

## Report Structure

CloudSecure generates comprehensive JSON reports:
```json
{
  "metadata": {
    "tool": "CloudStrike",
    "timestamp": "2026-02-26T02:00:00",
    "cloud_provider": "production (Multi-Account)"
  },
  "summary": {
    "total": 12,
    "critical": 8,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "posture": {
    "overall_score": 75,
    "cloud_breakdown": {
      "AWS": {
        "findings_count": 8,
        "critical": 6,
        "high": 1,
        "medium": 1,
        "low": 0,
        "score": 72
      },
      "Azure": {
        "findings_count": 3,
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 0,
        "score": 80
      },
      "GCP": {
        "findings_count": 1,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "score": 99
      }
    }
  },
  "findings": [
    {
      "severity": "critical",
      "title": "Public S3 Bucket via Policy",
      "resource": "sensitive-data-bucket",
      "cloud_provider": "AWS",
      "account_id": "123456789012",
      "account_name": "Production Main Account",
      "description": "Bucket policy grants public access"
    }
  ]
}
```

---

## Security Checks

### AWS (9 checks)
- **S3 Buckets**
  - Public access via ACL (CRITICAL)
  - Public access via bucket policy (CRITICAL)
  - Block Public Access disabled (CRITICAL)
  - Encryption disabled (HIGH)

- **IAM Privilege Escalation** (18 vectors)
  - Wildcard permissions (`*:*`, `iam:*`) - CRITICAL
  - CreateAccessKey - CRITICAL
  - AttachUserPolicy - CRITICAL
  - PutUserPolicy - CRITICAL
  - AttachRolePolicy - CRITICAL
  - PutRolePolicy - CRITICAL
  - AttachGroupPolicy - CRITICAL
  - PutGroupPolicy - CRITICAL
  - CreateLoginProfile - CRITICAL
  - UpdateLoginProfile - CRITICAL
  - PassRole + Lambda - CRITICAL
  - PassRole + EC2 - CRITICAL
  - PassRole + CloudFormation - CRITICAL
  - CreatePolicy - HIGH
  - SetDefaultPolicyVersion - HIGH
  - PassRole + DataPipeline - HIGH
  - PassRole + Glue - HIGH
  - AssumeRole - HIGH
  - InvokeFunction - HIGH
  - RunInstances - HIGH

- **EC2 Metadata**
  - IMDSv1 enabled (CRITICAL)

### Azure (3 checks)
- **Storage Containers**
  - Public blob containers (CRITICAL)

- **RBAC Roles**
  - Owner role assignment (CRITICAL)
  - User Access Administrator role (CRITICAL)
  - Contributor role assignment (HIGH)

- **VM Metadata**
  - IMDS accessible (CRITICAL)

### GCP (3 checks)
- **Cloud Storage**
  - Public buckets - allUsers (CRITICAL)
  - Public buckets - allAuthenticatedUsers (HIGH)

- **IAM Bindings**
  - Owner role (CRITICAL)
  - Editor role (HIGH)
  - Public role binding - allUsers (CRITICAL)
  - Public role binding - allAuthenticatedUsers (HIGH)

- **Compute Metadata**
  - IMDS accessible (CRITICAL)

---

## Testing

Run automated tests:
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/unit/test_aws.py
```

Current coverage: **40%** with **23 passing tests**

---

## Documentation

- [Detailed Usage Guide](USAGE.md)
- [Configuration Example](config/environments.example.yml)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## Security Best Practices

1. **Use Read-Only Credentials**
   - AWS: `SecurityAudit` managed policy
   - Azure: `Reader` role
   - GCP: `Viewer` role

2. **Protect Configuration Files**
   - Add `config/environments.yml` to `.gitignore`
   - Never commit real credentials or account IDs

3. **Run Regularly**
   - Schedule weekly scans
   - Compare against baseline for drift
   - Integrate into CI/CD pipelines

4. **Prioritize Findings**
   - Address CRITICAL findings immediately
   - Plan HIGH findings for next sprint
   - Track MEDIUM/LOW for compliance

---

## Roadmap

- [ ] HTML/PDF report generation
- [ ] Slack/Email notifications
- [ ] Custom check framework
- [ ] Remediation automation
- [ ] Compliance frameworks (CIS, NIST, SOC2)
- [ ] Web dashboard
- [ ] API endpoint scanning
- [ ] Container security checks

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Built with [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) for AWS
- Uses [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python)
- Powered by [Google Cloud Python Client](https://github.com/googleapis/google-cloud-python)
- CLI powered by [Rich](https://github.com/Textualize/rich)

---

## Contact

Email: [islamannafi@gmail.com]

Project Link: [https://github.com/DevAnnafi/CloudSecure](https://github.com/DevAnnafi/CloudSecure)

---

<p align="center">
  Made By DevAnnafi for Cloud Security
</p>