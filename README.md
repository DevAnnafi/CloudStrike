# CloudSecure

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Cloud Providers](https://img.shields.io/badge/clouds-AWS%20%7C%20Azure%20%7C%20GCP-orange)

> CloudSecure is a comprehensive multi-cloud security scanner that identifies misconfigurations and security vulnerabilities across AWS, Azure, and Google Cloud Platform. Built for security professionals and DevOps teams, it provides actionable findings with detailed reports to strengthen your cloud security posture.

## Features

- **Multi-Cloud Coverage** - Scan AWS, Azure, and GCP from a single tool with unified reporting
- **Extensive Security Checks** - Detects 30+ misconfiguration types including public storage, IAM privilege escalation paths, and metadata service vulnerabilities
- **Professional CLI** - Rich terminal interface with color-coded output, progress indicators, and flexible scanning options
- **Zero Configuration** - Uses existing cloud credentials (AWS CLI, Azure CLI, gcloud) with no additional setup required
- **Detailed JSON Reports** - Generate comprehensive security reports with severity classifications and actionable remediation guidance

## What Gets Scanned

### AWS
- **S3 Buckets** - Public access settings, ACLs, bucket policies, encryption status
- **IAM** - 20+ privilege escalation vectors including dangerous role assignments and policy misconfigurations
- **EC2 Metadata** - IMDSv1 vs IMDSv2 detection

### Azure
- **Blob Storage** - Public container access levels and anonymous access detection
- **RBAC** - Overly permissive role assignments (Owner, Contributor, User Access Administrator)
- **VM Metadata** - Azure IMDS accessibility checks

### GCP
- **Cloud Storage** - Public bucket IAM policies and access controls
- **IAM** - Dangerous role bindings (Owner, Editor) and public access detection
- **Compute Metadata** - Metadata service accessibility

## Requirements

- Python 3.8 or higher
- Cloud CLI tools (for the clouds you want to scan):
  - AWS: [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
  - Azure: [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) logged in
  - GCP: [gcloud CLI](https://cloud.google.com/sdk/gcloud) authenticated

## Installation
```bash
# Clone the repository
git clone https://github.com/DevAnnafi/CloudSecure.git
cd CloudSecure

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Configure Cloud Credentials

**AWS:**
```bash
aws configure
```

**Azure:**
```bash
az login
```

**GCP:**
```bash
gcloud init
gcloud auth application-default login
```

### Run Scans

**Scan AWS:**
```bash
python src/cli.py scan --aws --output aws-report.json
```

**Scan Azure:**
```bash
python src/cli.py scan --azure --output azure-report.json
```

**Scan GCP:**
```bash
python src/cli.py scan --gcp --output gcp-report.json
```

**Scan All Clouds:**
```bash
python src/cli.py scan --all --verbose --output full-report.json
```

**Scan with AWS Profile:**
```bash
python src/cli.py scan --aws --profile my-profile --output report.json
```

## Sample Output
```bash
python src/cli.py scan --aws --verbose --output report.json
```
```
Scanning S3 buckets...
Scanning for IAM vulnerabilities...
Scanning for EC2 Instances...

 Scan Summary: 
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ Total    │ 3     │
│ Critical │ 2     │
│ High     │ 0     │
│ Medium   │ 1     │
│ Low      │ 0     │
└──────────┴───────┘
Report saved to report.json with 3 findings
```
## Multi-Account Scanning (v2)

CloudSecure v2 supports scanning multiple AWS accounts, Azure subscriptions, and GCP projects from a single configuration file.

### Setup

1. **Create a configuration file** (`config/environments.yml`):
```yaml
production:
  aws:
    - profile: prod-account-1
      name: "Production Main"
    - profile: prod-account-2
      name: "Production DR"
  azure:
    - subscription_id: "abc-123-def-456"
      name: "Production Subscription"
  gcp:
    - project_id: "my-prod-project"
      name: "Production GCP"

staging:
  aws:
    - profile: staging
      name: "Staging Account"
```

2. **Configure cloud credentials**:

**AWS:**
```bash
[prod-account-1]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET

[prod-account-2]
aws_access_key_id = YOUR_KEY
aws_secret_access_key = YOUR_SECRET
```

**Azure:**
```bash
az login
az account set --subscription "abc-123-def-456"
```

**GCP:**
```bash
gcloud auth application-default login
gcloud config set project my-prod-project
```

### Usage

**Scan a specific environment:**
```bash
python src/cli.py scan --environment production --config config/environments.yml --output report.json --verbose
```

**Single account mode (v1) still works:**
```bash
python src/cli.py scan --aws --output report.json
```

### Output

Multi-account reports include enhanced findings with account tracking:
```json
{
  "findings": [
    {
      "severity": "critical",
      "title": "Public S3 Bucket",
      "resource": "my-bucket",
      "cloud_provider": "AWS",
      "account_id": "123456789012",
      "account_name": "Production Main",
      "description": "Bucket grants public access"
    }
  ]
}
```

## Command Line Options
```
CloudSecure - Multi-Cloud Security Scanner

Options:
  --aws              Scan AWS resources
  --azure            Scan Azure resources
  --gcp              Scan GCP resources
  --all              Scan all cloud providers
  --output PATH      Output file path (required)
  --format FORMAT    Report format: json, html (default: json)
  --profile NAME     AWS profile name
  --verbose          Show detailed progress
```

## Running Tests
```bash
# Run unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=src --cov-report=html
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for security assessment of your own cloud infrastructure. Always ensure you have proper authorization before scanning any cloud environment. The authors are not responsible for misuse of this tool.

## Acknowledgments

Built with:
- [boto3](https://github.com/boto/boto3) - AWS SDK
- [azure-sdk-for-python](https://github.com/Azure/azure-sdk-for-python) - Azure SDK
- [google-cloud-python](https://github.com/googleapis/google-cloud-python) - GCP SDK
- [Rich](https://github.com/Textualize/rich) - Terminal formatting

---

**Made by DevAnnafi**