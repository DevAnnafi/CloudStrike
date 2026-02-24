import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.gcp.bucket_checker import BucketScanner
import subprocess

print("Starting GCP Storage scan...")
print("-" * 50)

# Get project ID
result = subprocess.run(['gcloud', 'config', 'get-value', 'project'], 
                       capture_output=True, text=True)
project_id = result.stdout.strip()

print(f"Using project: {project_id}\n")

scanner = BucketScanner(project_id)

try:
    findings = scanner.scan()
    
    print(f"✓ Scan complete!")
    print(f"  Public buckets found: {len(findings)}\n")
    
    if findings:
        print("CRITICAL:")
        for f in findings:
            print(f"  - {f['resource']}")
            print(f"    {f['description']}\n")
    else:
        print("No public buckets found!")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()