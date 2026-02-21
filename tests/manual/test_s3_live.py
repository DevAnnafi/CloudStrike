import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from scanners.aws.s3_checker import S3Scanner

print("Starting S3 security scan...")
print("-" * 50)

# Initialize scanner
scanner = S3Scanner()

# Run scan
try:
    findings = scanner.scan_buckets()
    
    # Print summary
    print(f"\n✓ Scan complete!")
    print(f"  Total buckets scanned: (check your AWS console)")
    print(f"  Security issues found: {len(findings)}\n")
    
    # Print findings grouped by severity
    critical = [f for f in findings if f['severity'] == 'critical']
    medium = [f for f in findings if f['severity'] == 'medium']
    
    if critical:
        print(f" CRITICAL ({len(critical)}):")
        for f in critical:
            print(f"  - {f['resource']}: {f['title']}")
    
    if medium:
        print(f" MEDIUM ({len(medium)}):")
        for f in medium:
            print(f"  - {f['resource']}: {f['title']}")
    
    if not findings:
        print(" No security issues found!")
        
except Exception as e:
    print(f" Error: {e}")