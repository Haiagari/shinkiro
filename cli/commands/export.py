"""
CLI Command: export - OzyRecon v8.3
Generates professional data exports (CSV/JSON) for external analysis.
"""

import click
import csv
import json
from pathlib import Path
from src.storage.database import SessionLocal
from src.storage.models import Subdomain, Vulnerability, Target
from src.core.logging import console

@click.command(name="export")
@click.argument("target_domain")
@click.option("--format", type=click.Choice(['csv', 'json']), default='csv', help="Export format")
@click.option("--output", help="Output file path")
def export_data(target_domain, format, output):
    """Exports all discovered intelligence for a target."""
    db = SessionLocal()
    try:
        # 1. Fetch Data
        assets = db.query(Subdomain).filter(Subdomain.domain.like(f"%{target_domain}")).all()
        
        if not assets:
            console.print(f"[red]No data found for target '{target_domain}'.[/red]")
            return

        data = []
        for a in assets:
            data.append({
                "domain": a.domain,
                "status": "LIVE" if a.is_live else "DEAD",
                "ip": a.ip or "",
                "http_status": a.http_status,
                "title": a.title or "",
                "technologies": ",".join(a.technologies or []),
                "impact": a.business_impact,
                "asn": a.asn or ""
            })

        # 2. Export
        out_path = output or f"exports/{target_domain}_report.{format}"
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)

        if format == 'csv':
            with open(out_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        console.print(f"[bold green]✅ Export successful![/bold green] Saved to: [cyan]{out_path}[/cyan]")
        
    finally:
        db.close()
