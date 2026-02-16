from rich import print
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.spinner import Spinner
from enums import Severity
from contextlib import contextmanager
from rich.traceback import install

install(show_locals=True)

## Color Coded Output
console = Console()

color_sev = {
    Severity.CRITICAL : "bold red",
    Severity.HIGH : "red",
    Severity.MEDIUM : "yellow",
    Severity.LOW : "blue",
    Severity.INFO : "green",
    "success" : "bold green",
    "debug" : "dim white"
}

def _log(message, severity):
    style = color_sev[severity]
    console.print(message, style=style)

def info(message):
    _log(message, Severity.INFO)

def warning(message):
    _log(message, Severity.MEDIUM)

def error(message):
    _log(message, Severity.CRITICAL)

def success(message):
    _log(message, "success")

def debug(message):
    _log(message, "debug")

## Progress Indicator
@contextmanager
def progress_context(total, description):
    progress = Progress(
        TextColumn("[progress.description]"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn()
    )
    with progress:
        task_id = progress.add_task(description, total=total)
        yield (progress, task_id)

# Spinner
@contextmanager  
def spinner_context(message, spinner_style="dots"):
    with console.status(message, spinner=spinner_style):
        yield
    





