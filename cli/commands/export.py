"""
CLI Command: export - OzyRecon v8.3
Generates professional data exports (CSV/JSON) for external analysis.
"""

import click
import csv
import json
from pathlib import Path

from sqlalchemy import or_

from cli.shared import console, render_outcome
from src.core.target_normalizer import normalize_lookup_target
from src.storage.database import SessionLocal
from src.storage.models import Subdomain


@click.command(name="export")
@click.argument("target_domain")
@click.option("--format", type=click.Choice(["csv", "json"]), default="csv", help="Export format")
@click.option("--output", help="Output file path")
def export_data(target_domain, format, output):
    """Exports all discovered intelligence for a target."""
    db = SessionLocal()
    try:
        # 1. Fetch Data
        lookup_target = normalize_lookup_target(target_domain)
        assets = (
            db.query(Subdomain)
            .filter(
                or_(
                    Subdomain.domain == lookup_target,
                    Subdomain.domain.like(f"%.{lookup_target}"),
                )
            )
            .all()
        )

        if not assets:
            render_outcome(f"No data found for target '{target_domain}'.", border_style="yellow")
            return

        data = []
        for a in assets:
            data.append(
                {
                    "domain": a.domain,
                    "status": "LIVE" if a.is_live else "DEAD",
                    "ip": a.ip or "",
                    "http_status": a.http_status,
                    "title": a.title or "",
                    "technologies": ",".join(a.technologies or []),
                    "impact": a.business_impact,
                    "asn": a.asn or "",
                }
            )

        # 2. Export
        out_path = output or f"exports/{target_domain}_report.{format}"
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)

        if format == "csv":
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        render_outcome("Export successful!")
        console.print(f"Saved to: [cyan]{out_path}[/cyan]")

    finally:
        db.close()
