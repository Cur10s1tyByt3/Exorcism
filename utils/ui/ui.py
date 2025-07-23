from rich.console import Console
from rich import traceback
from rich.logging import RichHandler
from rich.theme import Theme
import logging

traceback.install(show_locals=True)

custom_theme = Theme(
    {
        "info": "dim cyan",
        "warning": "magenta",
        "danger": "bold red",
        "success": "bold green",
        "highlight": "bold yellow",
    }
)

console = Console(theme=custom_theme)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)

__all__ = ["console"]
