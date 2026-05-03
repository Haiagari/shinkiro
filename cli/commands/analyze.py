"""
CLI Command: analyze - OzyRecon v8.3
AI-Powered intelligence analysis for targets in the terminal.
"""

import click
from rich.panel import Panel
from rich.markdown import Markdown
from src.storage.database import SessionLocal
from src.storage.models import Subdomain, Vulnerability
from src.intelligence.ai_analyzer import ai_analyst
from src.core.logging import console

@click.command(name="analyze")
@click.argument("target_host")
def analyze(target_host):
    """Deep AI analysis of a specific host or target."""
    db = SessionLocal()
    try:
        # 1. Gather context about the target
        asset = db.query(Subdomain).filter(Subdomain.domain == target_host).first()
        if not asset:
            console.print(f"[red]Host '{target_host}' not found in database.[/red]")
            return

        vulns = db.query(Vulnerability).filter(Vulnerability.host == target_host).all()

        asset_data = {
            "domain": asset.domain,
            "semantic_labels": asset.semantic_labels or [],
            "business_impact": asset.business_impact or "LOW",
            "technologies": asset.technologies or [],
            "title": asset.title or "Unknown"
        }

        # 2. Run AI Narrative
        console.print(f"[bold blue]🧠 Analyzing {target_host} via Sentinel AI...[/bold blue]")
        analysis = ai_analyst.generate_finding_narrative(asset_data)

        # 3. Present Results
        console.print(Panel(
            f"[bold cyan]AI Impact Assessment[/bold cyan]\n\n"
            f"{analysis.get('analysis')}\n\n"
            f"[bold orange1]Business Impact:[/bold orange1] {analysis.get('business_impact')}",
            title=f"INTELLIGENCE REPORT: {target_host}",
            border_style="blue"
        ))

        if analysis.get('recommendations'):
            recs_md = "### Remediation Steps\n"
            for r in analysis['recommendations']:
                recs_md += f"* {r}\n"
            console.print(Markdown(recs_md))

        # v8.3.2 - New: Remediation Autopilot (Idea 2)
        if analysis.get('remediation_snippet'):
            from rich.syntax import Syntax
            snippet = analysis['remediation_snippet']
            console.print(f"\n[bold green]🛠️ Remediation Autopilot - Patch Suggestion:[/bold green]")
            console.print(f"[dim]{snippet.get('description', '')}[/dim]")
            
            syntax = Syntax(
                snippet.get('code', ''),
                snippet.get('language', 'bash'),
                theme="monokai",
                line_numbers=True
            )
            console.print(Panel(syntax, border_style="green", title="PROPOSED PATCH"))

    finally:
        db.close()
