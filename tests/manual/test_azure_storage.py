import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.azure.storage_checker import StorageChecker

print("Starting Azure Storage scan...")
print("-" * 50)

# Get subscription ID from Azure CLI config
import subprocess
result = subprocess.run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'], 
                       capture_output=True, text=True)
subscription_id = result.stdout.strip()

print(f"Using subscription: {subscription_id}\n")

scanner = StorageChecker(subscription_id)

try:
    findings = scanner.scan()
    
    print(f"✓ Scan complete!")
    print(f"  Public containers found: {len(findings)}\n")
    
    if findings:
        print(" CRITICAL:")
        for f in findings:
            print(f"  - {f['resource']}")
            print(f"    Access level: {f['description']}\n")
    else:
        print(" No public containers found!")
        
except Exception as e:
    print(f" Error: {e}")
    import traceback
    traceback.print_exc()