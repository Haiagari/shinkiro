"""
CLI command to generate reports for OzyRecon.
"""

import sys
import os
from pathlib import Path
from datetime import datetime

import click
from rich.console import Console

from src.reporting.jinja_engine import Jinja2ReportEngine
from src.storage.database import SessionLocal
from src.storage.models import Target
from cli.shared import console, ensure_config_loaded, handle_exception

@click.command(name='report')
@click.argument('target')
@click.option(
    '--format', 
    type=click.Choice(['html', 'pdf', 'both'], case_sensitive=False), 
    default='html',
    help='Output format for the report.'
)
@click.option(
    '--output', 
    type=click.Path(), 
    default='reports/',
    help='Directory to save the report files.'
)
@click.option(
    '--template', 
    type=str, 
    default='layouts/report.j2',
    help='Path to the Jinja2 template (relative to templates dir).'
)
@ensure_config_loaded()
def report(target: str, format: str, output: str, template: str):
    """
    Generate a security report for TARGET.
    
    TARGET can be a domain or IP that has been previously scanned.
    """
    try:
        # 1. Validate target exists in database
        db = SessionLocal()
        try:
            target_obj = db.query(Target).filter(Target.domain == target).first()
            if not target_obj:
                console.print(f"[bold red]✗ Error:[/bold red] Target '[bold]{target}[/bold]' not found in database.")
                console.print("[dim]Make sure you have run a scan for this target first.[/dim]")
                sys.exit(1)
        finally:
            db.close()

        # 2. Initialize Report Engine
        with console.status(f"[bold cyan]Generating {format.upper()} report for {target}...", spinner="dots"):
            engine = Jinja2ReportEngine()
            
            # 3. Generate Report
            # Ensure output directory exists
            os.makedirs(output, exist_ok=True)
            
            report_path = engine.generate_report(
                target=target,
                format=format.lower(),
                output_dir=output,
                template=template
            )

        # 4. Success message
        if report_path:
            console.print(f"\n[bold success]✓ Report generated successfully![/bold success]")
            console.print(f"[info]Output path:[/info] [bold white]{report_path}[/bold white]")
            
            # If 'both' was requested, mention the directory
            if format.lower() == 'both':
                console.print(f"[dim]All report formats saved in: {os.path.abspath(output)}[/dim]")
        else:
            console.print("[red]✗ Failed to generate report.[/red]")
            sys.exit(1)

    except Exception as e:
        handle_exception(e)
        sys.exit(1)
