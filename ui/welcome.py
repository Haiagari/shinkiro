from __future__ import annotations

from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from .ozy import ozy_art
from .renderer import console


def _left(username: str, api_base: str, api_ok: bool, mode: str) -> Panel:
    t = Text()
    t.append("Welcome back, ", style="bold")
    t.append(f"{username}!\n\n", style="accent bold")
    t.append_text(ozy_art("ok" if api_ok else "neutral"))
    t.append("\n\n")
    t.append("User  · ", style="muted")
    t.append(f"{username}\n")
    t.append("API   · ", style="muted")
    t.append(f"{api_base} ●\n", style="host" if api_ok else "fail")
    t.append("Mode  · ", style="muted")
    t.append(f"{mode}\n", style="observe")
    t.append("State · ", style="muted")
    t.append("terminal command center")
    return Panel(t, border_style="accent", padding=(0, 1))


def _right(recent: list[dict]) -> Panel:
    t = Text()
    t.append("Quick start\n", style="accent bold")
    for cmd, desc in [
        ("scan <target>", "Lanza un scan real"),
        ("status", "Último estado"),
        ("overview", "Resumen operativo"),
        ("targets", "Targets monitoreados"),
        ("inspect <target>", "Abre un run"),
        ("watch <target>", "Sigue en vivo"),
        ("focus <target>", "Fija el activo"),
        ("diff <target>", "Compara runs"),
        ("export <target>", "Exporta resumen"),
        ("history", "Historial local"),
        ("doctor", "Diagnóstico del entorno"),
    ]:
        t.append("· ", style="muted")
        t.append(cmd, style="cmd")
        t.append(f"  {desc}\n", style="muted")

    t.append("\nRecent runs\n", style="accent bold")
    if not recent:
        t.append("Sin actividad reciente\n", style="muted")
    else:
        for item in recent[-3:]:
            icon = "[ok]✓[/ok]" if item.get("status") == "completed" else "[fail]✗[/fail]" if item.get("status") == "error" else "[warn]●[/warn]"
            t.append(f"  {item.get('target', 'n/a')}  ")
            t.append_text(Text.from_markup(icon))
            t.append(f"  {item.get('status', 'n/a')}\n")
    return Panel(t, border_style="muted", padding=(0, 1))


def print_welcome(
    username: str,
    api_base: str,
    api_ok: bool,
    mode: str = "INTERACTIVE",
    recent: list[dict] | None = None,
    version: str = "0.1.0",
) -> None:
    console.print()
    console.rule(
        f"[accent bold]🦉 BUG_BOUNTY_CLI v{version}[/]  "
        f"[muted]· {username} · {mode}[/]",
        style="accent",
        align="left",
    )
    console.print(
        Columns(
            [
                _left(username.split("@")[0].capitalize(), api_base, api_ok, mode),
                _right(recent or []),
            ],
            equal=True,
            expand=True,
        )
    )
    console.print()
    console.print(
        "  [muted]/help[/] ayuda  "
        "[muted]·[/]  [muted]scan[/] lanzar scan  "
        "[muted]·[/]  [muted]status[/] estado  "
        "[muted]·[/]  [muted]history[/] historial  "
        "[muted]·[/]  [muted]Ctrl+D[/] salir",
        style="dim",
    )
    console.print()
