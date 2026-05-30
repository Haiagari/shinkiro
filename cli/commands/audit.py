import click
from rich.table import Table
from src.storage.db_manager import db

from cli.shared import console, render_outcome, render_panel

@click.command()
@click.argument('target')
@click.option('--type', 'finding_type', default='secret', help='Type of findings to audit (secret, vulnerability)')
def audit(target, finding_type):
    """
    Manually triage and verify findings for a target.
    """
    render_panel(f"[bold blue]OzyRecon Audit Mode[/bold blue] - Target: [yellow]{target}[/yellow]", border_style="blue")
    
    # Simular recuperación de hallazgos desde el Storage
    # En una implementación real, leeríamos de la DB CAS o del inventario
    findings = db.get_assets(target) # Placeholder
    
    if not findings:
        render_outcome("No findings found for this target.", border_style="red")
        return

    table = Table(title=f"Auditing {finding_type.capitalize()} Findings")
    table.add_column("ID", style="dim")
    table.add_column("Type")
    table.add_column("Match/Detail")
    table.add_column("AI Verdict")
    
    # Por ahora mostramos un resumen de lo que el sistema "ve"
    for i, finding in enumerate(findings[:10]):
        # Simular triage de IA
        verdict = "[green]Likely Real[/green]" if i % 2 == 0 else "[red]False Positive[/red]"
        table.add_row(str(i), finding.get('type', 'Unknown'), str(finding.get('match', '...')), verdict)
    
    console.print(table)
    render_panel("Use 'ozy analyze <host>' for a full AI-driven narrative report.", border_style="cyan")

if __name__ == "__main__":
    audit()
