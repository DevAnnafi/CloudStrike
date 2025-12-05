# Import yaml for reading YAML configuration files.
import yaml 
# Import time for tracking execution durations.
import time
# Import typing modules for type hints.
from typing import *
# Import pathlib for safe path handling.
import pathlib
# Import logger functions from logger.py for showing messages.
from logger import print_success, print_info, print_error, print_warning

# Define a function that loads a YAML config file, prints success or error messages,
# and returns the parsed data.
def load_yaml_config(file_path: str) -> dict | None:
    try:
        with open(file_path, "r") as file:
            data = yaml.safe_load(".github/workflows/ci.yml")
        print_success(f"Successfully loaded config: {file_path}")
        return data
    except FileNotFoundError:
        print_error(f"Config file not found: {file_path}")
        return None
    except yaml.YAMLError as e:
        print_error(f"Error parsing YAML file {file_path}: {e}")
        return None


# Create a 'timer' decorator that records how long a function takes to run
# and logs the total runtime after the wrapped function executes.
def timer(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        total_time = end_time - start_time
        print_info(f"Function '{func.__name__}' executed in {total_time:.2f} seconds")
        return result
    return wrapper

# Define a function that saves a Python dictionary to a JSON file.
# Use try/except to catch file write errors and log accordingly.
def save_json(file_path: str, data: dict):
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        print_success(f"Data successfully saved to {file_path}")
    except Exception as e:
        print_error(f"Failed to save data to {file_path}: {e}")