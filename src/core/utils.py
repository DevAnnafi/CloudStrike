from datetime import datetime
from pathlib import Path

def format_timestamp_human(timestamp):
    return timestamp.strftime("%B %d, %Y at %I:%M %p")

def format_timestamp_filename(timestamp):
    return timestamp.strftime("%Y-%m-%d_%H-%M-%S")
    
def ensure_directory_exists(filepath):
    directory = Path(filepath).parent
    directory.mkdir(parents=True, exist_ok=True)

def validate_output_path(path):
    return path.endswith(".json")