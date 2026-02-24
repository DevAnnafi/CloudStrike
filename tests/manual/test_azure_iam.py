import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.azure.iam_analyzer import RBACAnalyzer
import subprocess

print("Starting Azure RBAC scan...")
print("-" * 50)

# Get subscription ID
result = subprocess.run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'], 
                       capture_output=True, text=True)
subscription_id = result.stdout.strip()

print(f"Using subscription: {subscription_id}\n")

scanner = RBACAnalyzer(subscription_id)

try:
    findings = scanner.scan()
    
    print(f"✓ Scan complete!")
    print(f"  Overly permissive role assignments found: {len(findings)}\n")
    
    if findings:
        print("CRITICAL:")
        for f in findings:
            print(f"  - Principal: {f['resource']}")
            print(f"    {f['description']}\n")
    else:
        print("No overly permissive role assignments found!")
        
except Exception as e:
    print(f" Error: {e}")
    import traceback
    traceback.print_exc()