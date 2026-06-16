"""
CLI Command: paths - OzyRecon v8.3
Analyzes and visualizes critical attack paths in the terminal.
"""

import click
from rich.table import Table
from rich.tree import Tree
from src.storage.database import SessionLocal
from src.intelligence.analysis.path_analyzer import get_attack_paths
from cli.shared import console, render_outcome, render_panel

@click.command(name="paths")
@click.argument("target_domain")
def paths(target_domain):
    """Analyze critical attack vectors and lateral movement paths."""
    db = SessionLocal()
    try:
        render_panel(f"[bold blue]🧬 Simulating Attack Paths for {target_domain}...[/bold blue]", border_style="blue")
        attack_paths = get_attack_paths(db, target_domain)
        
        if not attack_paths:
            render_outcome("No clear lateral movement paths identified from current findings.")
            return

        for p in attack_paths:
            risk_color = "red" if p.get('risk_score', 0) >= 80 else "orange1"
            
            tree = Tree(f"[bold {risk_color}]Entry Point: {p['entry_point']}[/bold {risk_color}]")
            vector = tree.add(f"[cyan]Vector: {p['vector']}[/cyan]")
            
            if 'vulnerabilities' in p:
                vulns = vector.add("[bold red]Vulnerabilities Found[/bold red]")
                for v in p['vulnerabilities']:
                    vulns.add(v)
            
            if 'lateral_targets' in p:
                targets = vector.add("[bold yellow]Lateral Targets (Shared IP)[/bold yellow]")
                for t in p['lateral_targets'][:10]: # Limit display
                    targets.add(t)
                if len(p['lateral_targets']) > 10:
                    targets.add(f"[dim]... and {len(p['lateral_targets']) - 10} more[/dim]")
            
            if 'description' in p:
                vector.add(f"[dim]{p['description']}[/dim]")

            console.print(tree)
            console.print()

    finally:
        db.close()
