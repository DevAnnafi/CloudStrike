🛡️ **CloudStrike -- Multi‑Cloud Pentesting Framework**
======================================================

CloudStrike is an offensive security toolkit designed for **red teams, penetration testers, and cloud security engineers**.\
It automates the enumeration and detection of **high‑impact misconfigurations** across AWS, Azure, and GCP environments --- the exact weaknesses adversaries target during real breaches.

CloudStrike consolidates reconnaissance, misconfiguration scanning, and privilege escalation detection into one streamlined framework.

> ⚠️ **Legal Notice:** CloudStrike is for authorized testing only.\
> Using this tool on environments you do not own or have explicit permission to test is illegal.

* * * * *

🚀 **Features**
---------------

### 🟦 **Amazon Web Services (AWS)**

| Module | Description |
| --- | --- |
| **S3 Public Access Scanner** | Detects buckets exposed to `AllUsers` and `AuthenticatedUsers`. |
| **IAM Privilege Escalation Detector** | Flags dangerous permissions like `iam:PassRole`, `sts:AssumeRole`, and keys that enable escalation. |
| **EC2 Metadata Exposure** | Checks if IMDSv1 or IMDSv2 is configured properly and enumerates exposed metadata. |
| **Resource Enumeration** | Lists users, roles, EC2 instances, security misconfigurations. |

* * * * *

### 🟪 **Microsoft Azure**

| Module | Description |
| --- | --- |
| **Blob Storage Exposure** | Detects public containers and misconfigured access levels. |
| **Role & IAM Analyzer** | Identifies over‑permissioned identities and attack paths. |
| **Azure Metadata Probe** | Checks access to Azure's metadata endpoint for misconfigurations. |

* * * * *

### 🟥 **Google Cloud Platform (GCP)**

| Module | Description |
| --- | --- |
| **Public Bucket Detection** | Flags buckets accessible to `allUsers` or `allAuthenticatedUsers`. |
| **GCP IAM Escalation Detection** | Identifies unsafe roles and privilege escalation vectors. |
| **GCP Metadata Scanning** | Probes instance metadata for token leakage and insecure exposure. |

* * * * *

🔧 **Tech Stack**
-----------------

-   **Python 3.11+**

-   `boto3` (AWS)

-   `google-cloud-storage` (GCP)

-   `azure-identity` & `azure-mgmt-resource` (Azure)

-   `rich` for CLI styling

-   `PyYAML` for config loading

-   `requests` for metadata probing

* * * * *

📁 **Project Structure**
------------------------

```
cloudstrike/
│
├── cloudstrike/
│   ├── cli.py
│   ├── core/
│   │   ├── logger.py
│   │   ├── report.py
│   │   ├── utils.py
│   │   └── enums.py
│   │
│   ├── aws/
│   │   ├── s3_checker.py
│   │   ├── iam_enum.py
│   │   ├── metadata.py
│   │   └── ec2_enum.py
│   │
│   ├── azure/
│   ├── gcp/
│   └── config/
│
├── requirements.txt
├── README.md
├── LICENSE
└── .github/workflows/ci.yml`
```
* * * * *

🖥️ **Installation**
--------------------

`git clone https://github.com/<yourname>/CloudStrike.git
cd CloudStrike
pip install -r requirements.txt`

* * * * *

🕹️ **Usage**
-------------

CloudStrike uses a modular CLI:

### **AWS**

`python -m cloudstrike --aws-s3 --aws-iam --aws-meta`

### **Azure**

`python -m cloudstrike --azure-storage --azure-iam --azure-meta`

### **GCP**

`python -m cloudstrike --gcp-buckets --gcp-iam --gcp-meta`

* * * * *

📊 **Reporting**
----------------

CloudStrike automatically generates detailed JSON reports:

`cloudstrike_report.json`

Each module contributes:

-   Misconfiguration description

-   Severity level

-   Evidence

-   Recommended fixes

Future versions will include **HTML reports** & **attack path visualization**.

* * * * *

🧪 **Continuous Integration**
-----------------------------

CloudStrike comes with a full GitHub Actions pipeline:

-   Linting (`flake8`)

-   Automated tests

-   PR checks

-   Branch protection support

Located in:

`.github/workflows/ci.yml`

* * * * *

🧱 **Roadmap**
--------------

-   Add HTML/Markdown report generator

-   Add attack path graphing (IAM → escalation chain)

-   Add multi-threaded scanning engine

-   Add Terraform state leak detection

-   Add "CloudStrike Web" dashboard (FastAPI + React)

-   Add AWS/GCP/Azure lateral movement modules

* * * * *

📚 **Why CloudStrike Exists**
-----------------------------

Cloud misconfiguration remains the **#1 cause of cloud breaches**.\
Attackers don't exploit CPU bugs --- they exploit:

-   public buckets

-   IAM misconfigurations

-   metadata exposure

-   weak role boundaries

CloudStrike helps you detect these issues **before attackers do**.

* * * * *

🛡️ **Disclaimer**
------------------

CloudStrike is for **authorized environments only**.\
The author is not responsible for misuse or illegal activity.\
Use responsibly and ethically.

* * * * *

⭐ **Contributing**
------------------

Pull requests are welcome!

Please open issues for:

-   new modules

-   performance improvements

-   detection inaccuracies

-   false positives

* * * * *

🏁 **License**
--------------

MIT License.

* * * * *

🌐 **Author**
-------------

**CloudStrike by Annafi Islam**\
Built for offensive security engineers, pentesters, and cloud defenders.
