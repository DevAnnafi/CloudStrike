import sys
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.utils import (
    format_timestamp_human,
    format_timestamp_filename,
    ensure_directory_exists,
    validate_output_path
)

# Test timestamp formatting
now = datetime.utcnow()
print("Human format:", format_timestamp_human(now))
print("Filename format:", format_timestamp_filename(now))

# Test directory creation
test_path = "test_output/nested/deep/report.json"
ensure_directory_exists(test_path)
print(f"Directory created: {Path(test_path).parent.exists()}")

# Test path validation
print("Valid .json:", validate_output_path("report.json"))
print("Invalid .txt:", validate_output_path("report.txt"))
print("Invalid empty:", validate_output_path(""))