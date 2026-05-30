"""
Shared utilities for OzyRecon CLI.
Breaks circular imports between main CLI and subcommands.
"""

from functools import wraps
from pathlib import Path
from typing import Callable, Iterable, Any
import json

from rich.console import Console
from rich.panel import Panel
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


def render_panel(content: str, *, title: str | None = None, border_style: str = "cyan") -> None:
    """Render a consistent Rich panel for CLI messages."""
    console.print(Panel.fit(content, title=title, border_style=border_style))


def render_stage(step: str, title: str, detail: str, *, border_style: str = "cyan") -> None:
    """Render a stage panel with a numbered step label."""
    render_panel(
        f"[bold]{step} {title}[/bold]\n[dim]{detail}[/dim]",
        border_style=border_style,
    )


def render_plan(title: str, lines: Iterable[str], *, border_style: str = "bright_cyan") -> None:
    """Render a plan-like panel with multiple lines of guidance."""
    render_panel("\n".join(lines), title=title, border_style=border_style)


def render_outcome(message: str, *, border_style: str = "green") -> None:
    """Render a final outcome panel."""
    render_panel(f"[bold]{message}[/bold]", border_style=border_style)


def render_timing_summary(summary: dict[str, Any]) -> None:
    """Render a compact timing summary for slow tools."""
    lines = [
        f"[bold]Timed tools:[/bold] {summary.get('count', 0)}",
        f"[bold]Total elapsed:[/bold] {summary.get('total_elapsed', 0)}s",
    ]
    slowest = summary.get("slowest_tools", [])
    if slowest:
        lines.append("[bold]Slowest tools:[/bold]")
        for item in slowest[:5]:
            lines.append(f"  - {item.get('provider')} ({item.get('capability')}): {item.get('elapsed')}s [{item.get('status')}]")
    render_plan("Timing Summary", lines, border_style="magenta")


def load_timing_summary(out_dir: str | Path | None) -> dict[str, Any] | None:
    """Load flow timing summary from a session directory if present."""
    if not out_dir:
        return None
    path = Path(out_dir) / "flow_summary.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    timing = data.get("timing")
    return timing if isinstance(timing, dict) else None
