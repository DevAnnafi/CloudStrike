import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.aws import S3Scanner, IAMScanner, EC2MetaDataScanner

print("=" * 60)
print("COMPLETE AWS SECURITY SCAN")
print("=" * 60)

all_findings = []

# S3 Scanner
print("\n[1/3] Scanning S3 buckets...")
s3_scanner = S3Scanner()
s3_findings = s3_scanner.scan_buckets()
all_findings.extend(s3_findings)
print(f"  → Found {len(s3_findings)} S3 issues")

# IAM Scanner
print("\n[2/3] Scanning IAM privilege escalation...")
iam_scanner = IAMScanner()
iam_findings = iam_scanner.scan()
all_findings.extend(iam_findings)
print(f"  → Found {len(iam_findings)} IAM issues")

# Metadata Scanner
print("\n[3/3] Scanning EC2 metadata...")
metadata_scanner = EC2MetaDataScanner()
metadata_findings = metadata_scanner.scan()
all_findings.extend(metadata_findings)
print(f"  → Found {len(metadata_findings)} metadata issues")

# Summary
print("\n" + "=" * 60)
print(f"TOTAL FINDINGS: {len(all_findings)}")
print("=" * 60)

if all_findings:
    critical = [f for f in all_findings if f['severity'] == 'critical']
    medium = [f for f in all_findings if f['severity'] == 'medium']
    
    if critical:
        print(f"\n CRITICAL ({len(critical)}):")
        for f in critical:
            print(f"  - {f['title']}")
            print(f"    Resource: {f['resource']}")
    
    if medium:
        print(f"\n MEDIUM ({len(medium)}):")
        for f in medium:
            print(f"  - {f['title']}")
            print(f"    Resource: {f['resource']}")
else:
    print("\n No security issues found across all AWS services!")