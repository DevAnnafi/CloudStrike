import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.azure import StorageChecker, RBACAnalyzer, MetaDataProbe
import subprocess

print("=" * 60)
print("COMPLETE AZURE SECURITY SCAN")
print("=" * 60)

# Get subscription ID
result = subprocess.run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'], 
                       capture_output=True, text=True)
subscription_id = result.stdout.strip()

print(f"\nUsing subscription: {subscription_id}\n")

all_findings = []

# Storage Scanner
print("[1/3] Scanning Azure Storage...")
storage_scanner = StorageChecker(subscription_id)
storage_findings = storage_scanner.scan()
all_findings.extend(storage_findings)
print(f"  → Found {len(storage_findings)} storage issues")

# RBAC Scanner
print("\n[2/3] Scanning Azure RBAC...")
rbac_scanner = RBACAnalyzer(subscription_id)
rbac_findings = rbac_scanner.scan()
all_findings.extend(rbac_findings)
print(f"  → Found {len(rbac_findings)} RBAC issues")

# Metadata Scanner
print("\n[3/3] Scanning Azure Metadata...")
metadata_scanner = MetaDataProbe()
metadata_findings = metadata_scanner.scan()
all_findings.extend(metadata_findings)
print(f"  → Found {len(metadata_findings)} metadata issues")

# Summary
print("\n" + "=" * 60)
print(f"TOTAL FINDINGS: {len(all_findings)}")
print("=" * 60)

if all_findings:
    critical = [f for f in all_findings if f['severity'] == 'critical']
    
    if critical:
        print(f"\n CRITICAL ({len(critical)}):")
        for f in critical:
            print(f"  - {f['title']}")
            print(f"    Resource: {f['resource']}")
else:
    print("\n No security issues found across all Azure services!")