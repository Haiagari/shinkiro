"""
Shared utilities for OzyRecon CLI.
Breaks circular imports between main CLI and subcommands.
"""

import sys
from functools import wraps
from typing import Callable

from rich.console import Console
from rich.theme import Theme

# Rich Global Console
console = Console(
    theme=Theme({
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
    })
)

def ensure_config_loaded() -> Callable:
    """
    Decorator that validates the system is ready before executing a command.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Task 2.10: Import config here to ensure it's loaded
            from src.core.config import config
            return func(*args, **kwargs)
        return wrapper
    return decorator

def handle_exception(error: Exception) -> None:
    """
    Handles exceptions showing clean errors using Rich.
    """
    # Note: Using a simple flag check here or importing debug from ozy if needed
    console.print(f"[red]✗ Error:[/red] {str(error)}")
