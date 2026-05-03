import click
from rich.console import Console
from src.core.providers.gowitness import GowitnessProvider
from src.core.path_resolver import path_resolver

console = Console()

@click.command()
@click.argument('target')
def screenshot(target):
    """
    Take a screenshot of a target URL or file of URLs.
    """
    console.print(f"[bold cyan]📸 Visual Recon[/bold cyan] - Target: [yellow]{target}[/yellow]")
    
    provider = GowitnessProvider()
    
    if not provider.is_available():
        console.print("[red]Error: gowitness binary not found in tools/go/bin/[/red]")
        return

    console.print("[dim]Starting capture...[/dim]")
    output_path = provider.execute(target)
    
    if output_path:
        console.print(f"[green]✓ Success![/green] Screenshots saved in: [bold]{output_path}[/bold]")
    else:
        console.print("[red]Failed to take screenshot.[/red]")

if __name__ == "__main__":
    screenshot()
