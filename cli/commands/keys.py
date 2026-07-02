"""
CLI Commands for API Key Management - PromptWall v8.1
"""

import click
from rich.table import Table
from cli.shared import console, render_outcome, render_panel
from src.auth.key_store import key_store

@click.group(name="keys")
def keys():
    """Manage PromptWall API Keys and Scopes."""
    pass

@keys.command(name="create")
@click.argument("name")
@click.option("--scopes", default="sessions:read,analysis:read", help="Comma-separated scopes")
@click.option("--limit", default=60, help="Rate limit per minute")
@click.option("--prefix", default="ozy_live_", help="Key prefix (ozy_live_ or ozy_dev_)")
def create_key(name, scopes, limit, prefix):
    """Creates a new API key (Shown only once)."""
    scope_list = [s.strip() for s in scopes.split(",")]
    name, api_key = key_store.create_key(name, scope_list, rate_limit=limit, prefix=prefix)
    
    render_panel(
        f"[bold green]API Key Created Successfully![/bold green]\n\n"
        f"Name: [cyan]{name}[/cyan]\n"
        f"Scopes: [yellow]{', '.join(scope_list)}[/yellow]\n\n"
        f"SECRET KEY: [bold white]{api_key}[/bold white]\n\n"
        f"[bold red]WARNING: Save this key now. It will NEVER be shown again.[/bold red]",
        border_style="green",
    )

@keys.command(name="list")
def list_keys():
    """Lists all active API keys."""
    all_keys = key_store.list_keys()
    if not all_keys:
        render_outcome("No API keys found.", border_style="yellow")
        return

    table = Table(title="PromptWall API Key Registry")
    table.add_column("Name", style="cyan")
    table.add_column("Role", style="magenta")
    table.add_column("Scopes", style="yellow")
    table.add_column("Limit/min", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Last Used", style="dim")

    for k in all_keys:
        status = "[green]Enabled[/green]" if k["enabled"] else "[red]Disabled[/red]"
        table.add_row(
            k["name"],
            "admin" if "admin:*" in k["scopes"] else "custom",
            ", ".join(k["scopes"]),
            str(k["rate_limit_per_min"]),
            status,
            k["last_used_at"] or "Never"
        )
    
    console.print(table)

@keys.command(name="revoke")
@click.argument("name")
def revoke_key(name):
    """Permanently revokes an API key."""
    if click.confirm(f"Are you sure you want to revoke key '{name}'?"):
        if key_store.revoke_key(name):
            render_outcome(f"Key '{name}' revoked successfully.")
        else:
            render_outcome(f"Key '{name}' not found.", border_style="red")
