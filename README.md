# CloudStrike

Multi-Cloud Security Penetration Testing Framework

## Features

-  Multi-cloud support (AWS, Azure, GCP)
-  Comprehensive security scanning
-  Detailed reporting (HTML, JSON, PDF)
-  Vulnerability detection
-  Fast and efficient

## Installation
```bash
# Clone the repository
git clone https://github.com/DevAnnafi/CloudStrike.git
cd CloudStrike

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start
```bash
# Configure credentials
cp .env.example .env
# Edit .env with your cloud credentials

# Run a scan
python cli.py scan --provider aws --type quick
```

## Documentation

Coming soon...

## License

MIT License
