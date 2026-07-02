"""
CLI Command: inventory - PromptWall v8.3
Provides a professional terminal-based inventory of discovered assets.
"""

import click
from sqlalchemy import or_
from rich.table import Table

from cli.shared import console, render_outcome, render_panel
from src.core.target_normalizer import normalize_lookup_target
from src.storage.database import SessionLocal
from src.storage.models import Subdomain, Vulnerability, Target


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
        lookup_target = normalize_lookup_target(target_domain)
        target = db.query(Target).filter(Target.domain == lookup_target).first()
        if not target:
            render_outcome(f"Target '{target_domain}' not found in database.", border_style="red")
            return

        query = db.query(Subdomain).filter(
            or_(
                Subdomain.domain == lookup_target,
                Subdomain.domain.like(f"%.{lookup_target}"),
            )
        )
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
            impact_color = (
                "red"
                if a.business_impact == "CRITICAL"
                else "orange1"
                if a.business_impact == "HIGH"
                else "white"
            )

            table.add_row(
                a.domain,
                status,
                a.ip or "-",
                ", ".join(a.technologies or []),
                f"[{impact_color}]{a.business_impact}[/{impact_color}]",
            )

        render_panel(f"Asset Inventory: {target_domain}", border_style="blue")
        console.print(table)
    finally:
        db.close()


@inventory.command(name="vulns")
@click.argument("target_domain")
def list_vulns(target_domain):
    """Lists identified vulnerabilities for a target."""
    db = SessionLocal()
    try:
        lookup_target = normalize_lookup_target(target_domain)
        vulns = (
            db.query(Vulnerability)
            .filter(
                or_(
                    Vulnerability.host == lookup_target,
                    Vulnerability.host.like(f"%.{lookup_target}"),
                )
            )
            .all()
        )

        if not vulns:
            render_outcome(f"No vulnerabilities found for {target_domain}.")
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
            "low": "[bold blue]LOW[/bold blue]",
        }

        for v in vulns:
            table.add_row(sev_map.get(v.severity.lower(), v.severity), v.name, v.host, v.status)

        render_panel(f"Vulnerability Registry: {target_domain}", border_style="red")
        console.print(table)
    finally:
        db.close()
