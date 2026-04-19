from rich.console import Console
from rich.theme import Theme


THEME = Theme(
    {
        "accent": "bold #e5711d",
        "cmd": "#70c0ff",
        "host": "bold #22c55e",
        "fail": "bold #ef4444",
        "observe": "bold #f59e0b",
        "muted": "#6b7280",
        "warn": "bold #f59e0b",
        "ok": "bold #22c55e",
    }
)

console = Console(theme=THEME, highlight=False)
