"""
CLI Command: analyze - OzyRecon v8.3
AI-Powered intelligence analysis for targets in the terminal.
"""

import click
from rich.markdown import Markdown

from cli.shared import console, render_outcome, render_panel
from src.core.target_normalizer import normalize_lookup_target
from src.intelligence.ai_analyzer import ai_analyst
from src.storage.database import SessionLocal
from src.storage.models import Subdomain, Vulnerability


@click.command(name="analyze")
@click.argument("target_host")
def analyze(target_host):
    """Deep AI analysis of a specific host or target."""
    db = SessionLocal()
    try:
        # 1. Gather context about the target
        lookup_host = normalize_lookup_target(target_host)
        asset = db.query(Subdomain).filter(Subdomain.domain == lookup_host).first()
        if not asset:
            render_outcome(f"Host '{target_host}' not found in database.", border_style="red")
            return

        vulns = db.query(Vulnerability).filter(Vulnerability.host == lookup_host).all()

        asset_data = {
            "domain": asset.domain,
            "semantic_labels": asset.semantic_labels or [],
            "business_impact": asset.business_impact or "LOW",
            "technologies": asset.technologies or [],
            "title": asset.title or "Unknown",
            "vulns_found": len(vulns),
        }

        # 2. Run AI Narrative
        render_panel(
            f"[bold blue]🧠 Analyzing {target_host} via Sentinel AI...[/bold blue]",
            border_style="blue",
        )
        analysis = ai_analyst.generate_finding_narrative(asset_data)

        # 3. Present Results
        render_panel(
            f"[bold cyan]AI Impact Assessment[/bold cyan]\n\n"
            f"{analysis.get('analysis')}\n\n"
            f"[bold orange1]Business Impact:[/bold orange1] {analysis.get('business_impact')}",
            title=f"INTELLIGENCE REPORT: {target_host}",
            border_style="blue",
        )

        if analysis.get("recommendations"):
            recs_md = "### Remediation Steps\n"
            for r in analysis["recommendations"]:
                recs_md += f"* {r}\n"
            console.print(Markdown(recs_md))

        # v8.3.2 - New: Remediation Autopilot (Idea 2)
        if analysis.get("remediation_snippet"):
            from rich.syntax import Syntax

            snippet = analysis["remediation_snippet"]
            render_panel("🛠️ Remediation Autopilot - Patch Suggestion", border_style="green")
            console.print(f"[dim]{snippet.get('description', '')}[/dim]")

            syntax = Syntax(
                snippet.get("code", ""),
                snippet.get("language", "bash"),
                theme="monokai",
                line_numbers=True,
            )
            console.print(syntax)

    finally:
        db.close()
