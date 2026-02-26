# Contributing to CloudSecure

Thank you for your interest in contributing to CloudSecure! This document provides guidelines and instructions for contributing to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of experience level, gender identity, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, or nationality.

### Our Standards

**Positive behaviors include:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behaviors include:**
- Harassment, trolling, or discriminatory comments
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of unacceptable behavior may be reported by contacting the project team. All complaints will be reviewed and investigated promptly and fairly.

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:
- Python 3.8 or higher
- Git installed and configured
- A GitHub account
- Basic knowledge of cloud security concepts
- Familiarity with AWS, Azure, or GCP (depending on contribution area)

### Find an Issue

Good places to start:
1. Check the [Issues](https://github.com/YOUR_USERNAME/CloudSecure/issues) page
2. Look for issues labeled `good first issue` or `help wanted`
3. Comment on an issue to claim it before starting work
4. Ask questions if anything is unclear

---

## Development Setup

### 1. Fork and Clone
```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/CloudSecure.git
cd CloudSecure

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/CloudSecure.git
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### 4. Configure Cloud Credentials (for testing)

**AWS:**
```bash
aws configure --profile test-account
```

**Azure:**
```bash
az login
```

**GCP:**
```bash
gcloud auth application-default login
```

### 5. Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/unit/test_aws.py -v
```

---

## How to Contribute

### Types of Contributions

1. **Bug Fixes**
   - Fix existing issues
   - Improve error handling
   - Resolve edge cases

2. **New Features**
   - Add new security checks
   - Support additional cloud services
   - Enhance reporting capabilities

3. **Documentation**
   - Improve README
   - Add code comments
   - Write tutorials or guides

4. **Testing**
   - Add unit tests
   - Add integration tests
   - Improve test coverage

5. **Performance**
   - Optimize scan speed
   - Reduce memory usage
   - Improve error handling

---

## 📏 Coding Standards

### Python Style Guide

Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these specifics:

**Formatting:**
- 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings to all functions and classes

**Example:**
```python
def check_bucket_encryption(self, bucket_name):
    """
    Check if S3 bucket has default encryption enabled.
    
    Args:
        bucket_name (str): Name of the S3 bucket to check
        
    Returns:
        None: Adds finding to self.findings if encryption is disabled
    """
    try:
        self.s3_client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            self.findings.append({
                "severity": Severity.HIGH.value,
                "title": "S3 Bucket Encryption Disabled",
                "resource": bucket_name,
                "description": "Bucket does not have default encryption enabled"
            })
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `S3Scanner`, `IAMScanner`)
- **Functions**: `snake_case` (e.g., `scan_buckets`, `check_encryption`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_RETRIES`, `DEFAULT_REGION`)
- **Private methods**: Prefix with `_` (e.g., `_get_finding_key`)

### Code Organization
```
src/
├── core/              # Core functionality (config, reporting, drift)
├── scanners/          # Cloud-specific scanners
│   ├── aws/          # AWS scanners
│   ├── azure/        # Azure scanners
│   └── gcp/          # GCP scanners
└── utils/            # Utility functions
```

---

## Testing Guidelines

### Writing Tests

All new features must include tests:

**Unit Tests** (`tests/unit/`):
```python
def test_s3_public_bucket_detection():
    """Test that public S3 buckets are detected correctly."""
    with patch('scanners.aws.s3_checker.boto3.Session') as mock_session:
        mock_s3 = Mock()
        mock_s3.get_bucket_acl.return_value = {
            'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
        }
        mock_session.return_value.client.return_value = mock_s3
        
        scanner = S3Scanner()
        scanner.check_bucket_acl('test-bucket')
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0]['severity'] == 'critical'
```

**Integration Tests** (`tests/integration/`):
- Test real cloud API interactions (optional)
- Use test accounts with minimal permissions
- Clean up resources after tests

### Test Coverage Requirements

- Minimum 70% code coverage for new features
- All critical paths must be tested
- Edge cases should be covered

### Running Tests Locally
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test
pytest tests/unit/test_aws.py::test_s3_encryption_finding

# Run with coverage report
pytest --cov=src --cov-report=html tests/
```

---

## Pull Request Process

### 1. Create a Branch
```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 2. Make Changes

- Write clean, documented code
- Follow coding standards
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Changes

Use clear, descriptive commit messages:
```bash
# Good commit messages
git commit -m "Add GCS bucket versioning check"
git commit -m "Fix S3 encryption detection for KMS keys"
git commit -m "Update Azure RBAC severity levels"

# Bad commit messages (avoid these)
git commit -m "fixed bug"
git commit -m "updates"
git commit -m "wip"
```

**Commit Message Format:**
```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

### 4. Push and Create PR
```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:

**PR Title Format:**
```
[Type] Brief description of changes
```

Examples:
- `[Feature] Add Azure Key Vault scanning`
- `[Fix] Resolve IAM scanner timeout issue`
- `[Docs] Update multi-account configuration guide`

**PR Description Template:**
```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Related Issue
Fixes #(issue number)

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated (if applicable)
- [ ] All tests passing locally
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added that prove fix/feature works
```

### 5. Code Review

- Address reviewer feedback promptly
- Make requested changes in new commits
- Keep the conversation professional and constructive
- Update tests if requested

### 6. Merge

Once approved:
- Squash commits if requested
- Ensure CI/CD passes
- Maintainer will merge the PR

---

## Reporting Bugs

### Before Submitting

1. Check existing issues to avoid duplicates
2. Test with the latest version
3. Gather relevant information

### Bug Report Template
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. With configuration '...'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., macOS 13.0, Ubuntu 22.04]
- Python version: [e.g., 3.10.5]
- CloudSecure version: [e.g., 2.0.0]
- Cloud provider: [AWS/Azure/GCP]

**Logs/Screenshots**
```
Paste error logs here
```

**Additional context**
Any other relevant information.
```

---

## Suggesting Features

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
Description of the problem.

**Describe the solution you'd like**
Clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.

**Security Impact**
How this feature improves security posture.

**Additional context**
Any other context, screenshots, or examples.
```

---

## Good First Issues

Looking to contribute but not sure where to start? Try these:

### Beginner-Friendly
- Add new severity level to existing check
- Improve error messages
- Add docstrings to undocumented functions
- Fix typos in documentation

### Intermediate
- Add new security check for existing cloud service
- Improve test coverage
- Optimize scan performance
- Add support for new AWS/Azure/GCP region

### Advanced
- Add support for new cloud provider
- Implement custom check framework
- Add HTML report generation
- Create web dashboard

---

## Recognition

Contributors will be:
- Listed in the project README
- Credited in release notes
- Given contributor badge on GitHub
- Mentioned in project announcements

---

##  Community

### Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Email**: islamannafi@gmail.com for private inquiries

### Stay Updated

- Watch the repository for notifications
- Follow the project on Twitter: [@YourHandle](https://twitter.com/yourhandle)
- Read the [Changelog](CHANGELOG.md) for updates

---

##  Additional Resources

- [Python Best Practices](https://docs.python-guide.org/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

---

##  Thank You

Thank you for contributing to CloudSecure! Your efforts help make cloud security more accessible and effective for everyone.

---

**Questions?** Feel free to open an issue or reach out to the maintainers.

Happy Contributing! 