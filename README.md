# CloudStrike -- Cloud Pentesting Framework

CloudStrike is a multi-cloud pentesting toolkit designed to identify misconfigurations in AWS, Azure, and GCP environments.  

It focuses on real-world attack vectors used by red teams and cloud security engineers.

---

## 🔥 Features

### 🟦 AWS

- Public S3 bucket detection  

- IAM privilege escalation detection  

- EC2 metadata exposure  

- EC2 & IAM enumeration (expandable)

### 🟪 Azure

- Public blob container detection  

- Role assignments / privilege analysis  

- Metadata exposure checks

### 🟥 GCP

- Public bucket audit  

- Service account privilege enumeration  

- Metadata server probing

---

## 📦 Installation

git clone https://github.com/yourname/cloudstrike

cd cloudstrike

pip install -r requirements.txt

yaml

Copy code

---

## 🚀 Usage

python -m cloudstrike --aws-s3 --aws-iam --aws-meta

yaml

Copy code

---

## 🧪 CI/CD (GitHub Actions)

- Runs linting  

- Runs static checks  

- Runs test suite  

- Ensures pull requests meet quality bars

---

## ⚠️ Legal Notice

CloudStrike is intended for use in authorized environments only.  

Do not use it on systems you do not own.

---

## 📄 License

MIT
