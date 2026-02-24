import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.aws.metadata import EC2MetaDataScanner

print("Starting EC2 Metadata scan...")
print("-" * 50)

scanner = EC2MetaDataScanner()

try:
    findings = scanner.scan()
    
    print(f"\n✓ Scan complete!")
    print(f"  Metadata vulnerabilities found: {len(findings)}\n")
    
    if findings:
        print(" CRITICAL:")
        for f in findings:
            print(f"  - {f['title']}")
            print(f"    {f['description']}\n")
    else:
        print(" Not running on EC2 or IMDSv2 is enforced")
        
except Exception as e:
    print(f" Error: {e}")