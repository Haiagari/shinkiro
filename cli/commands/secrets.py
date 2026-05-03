"""
CLI Command: secrets - OzyRecon v8.3
Finds hardcoded secrets in JS files and discovered assets.
"""

import click
from rich.table import Table
from rich.panel import Panel
from src.storage.database import SessionLocal
from src.storage.models import Subdomain
from src.core.tool_manager import tool_manager
from src.intelligence.secret_finder import secret_finder
from src.core.logging import console
from src.utils import log

@click.command(name="secrets")
@click.argument("target_domain")
@click.option("--limit", default=10, help="Number of live hosts to spider")
@click.option("--threads", default=5, help="Scanning threads")
@click.option("--verify", is_flag=True, default=False, help="Use AI to verify findings and reduce false positives")
def secrets(target_domain, limit, threads, verify):
    """Deep Recon: Search for hardcoded secrets in JS files."""
    from src.intelligence.ai_analyzer import ai_analyst
    db = SessionLocal()
    try:
        # 1. Get Live Hosts
        live_assets = db.query(Subdomain).filter(
            Subdomain.domain.like(f"%{target_domain}"),
            Subdomain.is_live == 1
        ).limit(limit).all()

        if not live_assets:
            console.print(f"[yellow]No live assets found for {target_domain}. Run a live scan first.[/yellow]")
            return

        console.print(f"[bold blue]🕳️ Starting Deep Recon (Secret Hunting) for {target_domain}...[/bold blue]")
        all_secrets = []

        for asset in live_assets:
            target_url = f"https://{asset.domain}"
            log(f"Spidering {target_url} with Katana...", level="info")
            
            # 2. Run Katana to find JS files
            urls = tool_manager.run_capability("spidering", target_url, all_providers=True)
            if not urls:
                continue

            js_urls = [u for u in urls if u.endswith('.js')]
            if not js_urls:
                log(f"   No JS files found on {asset.domain}", level="debug")
                continue
            
            log(f"   Found {len(js_urls)} JS files. Scanning for secrets...", level="success")
            
            # 3. Scan JS files
            for js_url in js_urls[:20]: # Safety limit per host
                found = secret_finder.scan_url(js_url)
                if found:
                    all_secrets.extend(found)

        # 4. AI Verification
        if verify and all_secrets:
            console.print("[bold purple]🧠 Verifying findings with AI...[/bold purple]")
            all_secrets = ai_analyst.verify_secrets(all_secrets)

        # 5. Results
        if not all_secrets:
            console.print("[green]No secrets identified in the analyzed assets.[/green]")
        else:
            table = Table(title="💎 HARDCODED SECRETS IDENTIFIED", border_style="red")
            table.add_column("Type", style="bold red")
            table.add_column("Source (URL)", style="cyan")
            table.add_column("Match (Obfuscated)", style="yellow")
            table.add_column("Entropy", justify="center")
            table.add_column("Context", style="dim")

            for s in all_secrets:
                table.add_row(
                    s['type'],
                    s['source'],
                    s['match'],
                    str(s.get('entropy', '0')),
                    s['raw_context'][:50] + "..."
                )
            console.print(table)
            console.print(f"\n[bold red]TOTAL SECRETS FOUND: {len(all_secrets)}[/bold red]")

    finally:
        db.close()
