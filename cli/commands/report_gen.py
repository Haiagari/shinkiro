import click
from rich.console import Console
from src.reporting.html_generator import report_generator
from src.discovery.cloud_buckets import cloud_scanner
from src.intelligence.ai_analyzer import ai_analyst

console = Console()

@click.command(name="report")
@click.argument('target')
def generate_report(target):
    """
    Generate a professional HTML report for a target.
    """
    console.print(f"[bold blue]📊 Generating OzyRecon Elite Report for {target}...[/bold blue]")
    
    # 1. Scan for Cloud Buckets
    console.print("[dim]Scanning for Cloud Storage leaks...[/dim]")
    buckets = cloud_scanner.scan_domain(target)
    
    # 2. Gather findings (Simulado o desde DB)
    # En un caso real, esto vendría de db.get_findings(target)
    findings = [
        {"type": "Hardcoded API Key", "source": f"{target}/config.js", "impact": "High"},
        {"type": "Outdated Apache", "source": f"web.{target}", "impact": "Medium"}
    ]
    
    data = {
        "summary": "Se detectó una superficie de ataque moderada con exposición de infraestructura en la nube.",
        "findings": findings,
        "cloud_buckets": buckets
    }
    
    # 3. Generate HTML
    report_path = report_generator.generate(target, data)
    
    console.print(f"\n[green]✓ Report generated successfully![/green]")
    console.print(f"[bold]Path:[/bold] {report_path}")

if __name__ == "__main__":
    generate_report()
