# CloudSecure Usage Guide

## Installation

### Prerequisites
- Python 3.8+
- Cloud CLI tools installed:
  - AWS CLI (`aws-cli`)
  - Azure CLI (`az`)
  - Google Cloud SDK (`gcloud`)

### Install Dependencies
```bash
git clone https://github.com/YOUR_USERNAME/CloudSecure.git
cd CloudSecure
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Single Account Scanning (v1)

### AWS Only
```bash
# Uses default AWS credentials
python src/cli.py scan --aws --output aws-report.json

# Use specific AWS profile
python src/cli.py scan --aws --profile my-profile --output report.json
```

### Azure Only
```bash
# First login
az login

# Scan
python src/cli.py scan --azure --output azure-report.json
```

### GCP Only
```bash
# First login
gcloud auth application-default login

# Scan
python src/cli.py scan --gcp --output gcp-report.json
```

### All Clouds
```bash
python src/cli.py scan --all --output multi-cloud-report.json --verbose
```

---

## Multi-Account Scanning (v2)

### Step 1: Create Configuration File

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

development:
  aws:
    - profile: dev
      name: "Development Account"
```

### Step 2: Configure Cloud Credentials

**AWS Profiles** (`~/.aws/credentials`):
```ini
[prod-main]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[prod-dr]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE2
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY2
```

**Azure Login:**
```bash
az login
# List subscriptions
az account list --output table
```

**GCP Setup:**
```bash
gcloud auth application-default login
# Set default project
gcloud config set project my-prod-project-123
```

### Step 3: Run Multi-Account Scan
```bash
# Scan production environment
python src/cli.py scan \
  --environment production \
  --config config/environments.yml \
  --output production-report.json \
  --verbose

# Scan staging environment
python src/cli.py scan \
  --environment staging \
  --config config/environments.yml \
  --output staging-report.json
```

---

## Understanding the Output

### Report Structure
```json
{
  "metadata": {
    "tool": "CloudSecure",
    "version": "2.0.0",
    "cloud_provider": "production (Multi-Account)",
    "timestamp": "2026-02-25T16:30:00",
    "accounts_scanned": 5
  },
  "summary": {
    "total": 12,
    "critical": 8,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "findings": [
    {
      "severity": "critical",
      "title": "Public S3 Bucket",
      "resource": "sensitive-data-bucket",
      "cloud_provider": "AWS",
      "account_id": "123456789012",
      "account_name": "Production Main Account",
      "description": "Bucket grants public access via policy"
    }
  ]
}
```

### Severity Levels

- **CRITICAL**: Immediate action required (public resources, privilege escalation)
- **HIGH**: Fix soon (missing encryption, overly permissive roles)
- **MEDIUM**: Address eventually (compliance gaps, best practice violations)
- **LOW**: Nice to fix (optimization opportunities)

---

## Common Issues

### "Profile not found" Error
**Problem:** AWS profile doesn't exist in `~/.aws/credentials`

**Solution:** 
```bash
# List configured profiles
aws configure list-profiles

# Configure missing profile
aws configure --profile prod-main
```

### "Subscription not found" Error
**Problem:** Azure subscription ID is incorrect

**Solution:**
```bash
# List all subscriptions
az account list --output table

# Use correct subscription ID in config file
```

### "Project not found" Error
**Problem:** GCP project ID is wrong

**Solution:**
```bash
# List all projects
gcloud projects list

# Use correct project ID in config file
```

### Permission Denied Errors
**Problem:** Insufficient permissions to scan resources

**Solution:** Ensure your credentials have at least read-only access:
- AWS: `SecurityAudit` policy
- Azure: `Reader` role
- GCP: `Viewer` role

---

## Tips & Best Practices

1. **Start small**: Test with one account per cloud first
2. **Use read-only credentials**: Never give CloudSecure write permissions
3. **Run regularly**: Schedule scans weekly or after infrastructure changes
4. **Review findings**: Not all findings are critical - prioritize by severity
5. **Track trends**: Compare reports over time to measure security posture
6. **Automate**: Integrate into CI/CD pipelines for continuous monitoring

---

## Getting Help

- GitHub Issues: https://github.com/YOUR_USERNAME/CloudSecure/issues
- Documentation: https://github.com/YOUR_USERNAME/CloudSecure/blob/main/README.md