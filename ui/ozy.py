from __future__ import annotations

from rich.text import Text


_EYES = {
    "ok": ("[cyan]O[/cyan]", "[cyan]O[/cyan]"),
    "danger": ("[bold red]O[/bold red]", "[bold red]O[/bold red]"),
    "think": ("[yellow]-[/yellow]", "[yellow]-[/yellow]"),
    "scan": ("[orange1]@[/orange1]", "[orange1]@[/orange1]"),
    "neutral": ("O", "O"),
}


def ozy_art(state: str = "ok") -> Text:
    l, r = _EYES.get(state, _EYES["ok"])
    t = Text()
    t.append(",___,\n", style="cyan")
    t.append("[", style="cyan")
    t.append_text(Text.from_markup(l))
    t.append(".", style="cyan")
    t.append_text(Text.from_markup(r))
    t.append("]", style="cyan")
    t.append("   BUG BOUNTY CLI ", style="bold")
    t.append("v0.1.0\n", style="accent")
    t.append("/)__)", style="cyan")
    t.append('   "Nunca confíes, siempre verifica."\n', style="dim")
    t.append('-"--"-', style="cyan")
    return t


def ozy_compact() -> str:
    return "🦉 Ozy-CLI"
