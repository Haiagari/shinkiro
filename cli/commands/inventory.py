"""
CLI Command: inventory - OzyRecon v8.3
Provides a professional terminal-based inventory of discovered assets.
"""

import click
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from src.storage.database import SessionLocal
from src.storage.models import Subdomain, Vulnerability, Target
from src.core.logging import console

@click.group(name="inventory")
def inventory():
    """Manage and view discovered assets inventory."""
    pass

@inventory.command(name="assets")
@click.argument("target_domain")
@click.option("--live", is_flag=True, help="Show only live hosts")
@click.option("--limit", default=50, help="Number of assets to show")
def list_assets(target_domain, live, limit):
    """Lists subdomains and assets for a specific target."""
    db = SessionLocal()
    try:
        target = db.query(Target).filter(Target.domain == target_domain).first()
        if not target:
            console.print(f"[red]Target '{target_domain}' not found in database.[/red]")
            return

        query = db.query(Subdomain).filter(Subdomain.domain.like(f"%{target_domain}"))
        if live:
            query = query.filter(Subdomain.is_live == 1)
        
        assets = query.limit(limit).all()

        table = Table(title=f"Asset Inventory: {target_domain}", border_style="blue")
        table.add_column("Subdomain", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("IP Address", style="magenta")
        table.add_column("Tech Stack", style="yellow")
        table.add_column("Impact", justify="center")

        for a in assets:
            status = "[green]LIVE[/green]" if a.is_live else "[dim]DEAD[/dim]"
            impact_color = "red" if a.business_impact == "CRITICAL" else "orange1" if a.business_impact == "HIGH" else "white"
            
            table.add_row(
                a.domain,
                status,
                a.ip or "-",
                ", ".join(a.technologies or []),
                f"[{impact_color}]{a.business_impact}[/{impact_color}]"
            )
        
        console.print(table)
    finally:
        db.close()

@inventory.command(name="vulns")
@click.argument("target_domain")
def list_vulns(target_domain):
    """Lists identified vulnerabilities for a target."""
    db = SessionLocal()
    try:
        vulns = db.query(Vulnerability).filter(Vulnerability.host.like(f"%{target_domain}")).all()

        if not vulns:
            console.print(f"[green]No vulnerabilities found for {target_domain}.[/green]")
            return

        table = Table(title=f"Vulnerability Registry: {target_domain}", border_style="red")
        table.add_column("Severity", justify="center")
        table.add_column("Name", style="bold")
        table.add_column("Host", style="cyan")
        table.add_column("Status", justify="center")

        sev_map = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high": "[bold orange1]HIGH[/bold orange1]",
            "medium": "[bold yellow]MEDIUM[/bold yellow]",
            "low": "[bold blue]LOW[/bold blue]"
        }

        for v in vulns:
            table.add_row(
                sev_map.get(v.severity.lower(), v.severity),
                v.name,
                v.host,
                v.status
            )
        
        console.print(table)
    finally:
        db.close()
