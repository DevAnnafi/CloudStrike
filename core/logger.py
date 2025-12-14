# Import the Console class and Theme class from rich for colored output.
from rich.console import Console
from rich.theme import Theme

# Create a custom color theme dictionary that defines styles for info, warning,
# error, and success messages.

colored_messages = Theme({
    "info" : "white",
    "warning" : "red",
    "error" : "yellow",
    "success" : "green"
})

# Initialize a Console object using the custom theme.

console = Console(theme=colored_messages)


# Define a function to print informational messages.
def print_info(msg):
    print(f"[Informational] {msg}")


# Define a function to print warning messages.
def print_warning(msg):
    print(f"[Warning] {msg}")

# Define a function to print error messages.
def print_error(msg):
    print(f"[Error] {msg}")

# Define a function to print success messages.
def print_success(msg):
    print(f"[Successful] {msg}")

