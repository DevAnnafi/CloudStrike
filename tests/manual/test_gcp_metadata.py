import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.gcp.metadata_scanner import MetaDataScanner

print("Starting GCP Metadata scan...")
print("-" * 50)

scanner = MetaDataScanner()

try:
    findings = scanner.scan()
    
    print(f"\nScan complete!")
    print(f"Metadata vulnerabilities found: {len(findings)}\n")
    
    if findings:
        print("CRITICAL:")
        for f in findings:
            print(f"- {f['title']}")
            print(f"{f['description']}\n")
    else:
        print("Not running on GCP VM or IMDS is secure")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()