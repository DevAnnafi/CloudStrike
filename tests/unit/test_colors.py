import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.logger import info, warning, error, success, debug

print("\n=== Testing Color-Coded Severity Levels ===\n")

info("This should be GREEN - Info level message")
warning("This should be YELLOW - Warning level message")
error("This should be BOLD RED - Error level message")
success("This should be BOLD GREEN - Success message")
debug("This should be DIM WHITE - Debug message")

print("\n=== Test Complete ===\n")