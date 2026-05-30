"""Scope command group for batch-friendly scope management."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import click
import yaml

from cli.shared import console, render_outcome

SCOPE_FILE_PATH = Path("config/scope.yaml")


def load_scope() -> dict:
    """Load the scope YAML file or return an empty payload."""
    if not SCOPE_FILE_PATH.exists():
        return {}
    with SCOPE_FILE_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def save_scope(data: dict) -> None:
    """Persist the scope file atomically."""
    SCOPE_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, dir=SCOPE_FILE_PATH.parent, suffix=".tmp", encoding="utf-8") as tmp:
        yaml.safe_dump(data, tmp, sort_keys=False)
        temp_path = Path(tmp.name)
    temp_path.replace(SCOPE_FILE_PATH)


def _ensure_lists(data: dict) -> dict:
    data.setdefault("allowed_domains", [])
    data.setdefault("forbidden_patterns", [])
    return data


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _unique_merge(existing: list[str], incoming: list[str]) -> tuple[list[str], list[str]]:
    seen = set(existing)
    updated = list(existing)
    added: list[str] = []
    for item in incoming:
        normalized = _normalize_domain(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        updated.append(normalized)
        added.append(normalized)
    return updated, added

@click.group(name="scope")
def scope():
    """Manage target scope and authorization."""
    pass

@scope.command(name="list")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output scope as JSON")
def list_scope(json_output: bool):
    """List current allowed domains and forbidden patterns."""
    data = _ensure_lists(load_scope())
    allowed = data.get("allowed_domains", [])
    forbidden = data.get("forbidden_patterns", [])

    if json_output:
        click.echo(yaml.safe_dump(data, sort_keys=False).strip())
        return
    
    console.print("\n[bold cyan]Allowed Domains:[/bold cyan]")
    for domain in allowed:
        console.print(f"  - {domain}")
        
    console.print("\n[bold red]Forbidden Patterns:[/bold red]")
    for pattern in forbidden:
        console.print(f"  - {pattern}")

@scope.command(name="add")
@click.argument("domains", nargs=-1)
def add_domain(domains: tuple[str, ...]):
    """Add one or more domains to the allowed list."""
    if not domains:
        raise click.ClickException("Pass at least one domain to add.")

    data = _ensure_lists(load_scope())
    allowed = data.get("allowed_domains", [])
    updated, added = _unique_merge(allowed, list(domains))
    data["allowed_domains"] = updated
    save_scope(data)

    if added:
        render_outcome(f"Added {len(added)} domain(s) to scope.")
        for domain in added:
            console.print(f"[green]+ {domain}[/green]")
    else:
        console.print("[yellow]No new domains were added.[/yellow]")

@scope.command(name="remove")
@click.argument("domains", nargs=-1)
def remove_domain(domains: tuple[str, ...]):
    """Remove one or more domains from the allowed list."""
    if not domains:
        raise click.ClickException("Pass at least one domain to remove.")

    data = _ensure_lists(load_scope())
    allowed = data.get("allowed_domains", [])
    normalized = {_normalize_domain(domain) for domain in domains}
    remaining = [domain for domain in allowed if _normalize_domain(domain) not in normalized]
    removed = len(allowed) - len(remaining)
    data["allowed_domains"] = remaining
    save_scope(data)

    if removed:
        render_outcome(f"Removed {removed} domain(s) from scope.")
    else:
        console.print("[yellow]No matching domains were found.[/yellow]")

@scope.command(name="import")
@click.argument("file_path", type=click.Path(exists=True))
def import_scope(file_path):
    """Import domains from a text file (one per line)."""
    with open(file_path, "r", encoding="utf-8") as f:
        new_domains = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    
    if not new_domains:
        console.print("[yellow]No domains found in file.[/yellow]")
        return
        
    data = _ensure_lists(load_scope())
    allowed = data.get("allowed_domains", [])

    updated, added = _unique_merge(allowed, new_domains)
    data["allowed_domains"] = updated
    save_scope(data)

    if added:
        render_outcome(f"Imported {len(added)} target(s) from '{file_path}'.")
    else:
        console.print("[yellow]All targets already in scope.[/yellow]")
