import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.config import MultiAccountConfig

print("Testing MultiAccountConfig...")

# Test loading valid config
config = MultiAccountConfig("config/environments.yml")
config.load()

print(" Config loaded successfully")
print(f"Environments: {list(config.config.keys())}")

# Test getting environment
prod = config.get_environment("production")
print(f"\n Production environment:")
print(f"  AWS accounts: {len(prod.get('aws', []))}")
print(f"  Azure subscriptions: {len(prod.get('azure', []))}")
print(f"  GCP projects: {len(prod.get('gcp', []))}")

print("\nAll tests passed!")