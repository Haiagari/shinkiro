import click
from src.core.providers.gowitness import GowitnessProvider
from src.core.path_resolver import path_resolver

from cli.shared import console, render_outcome, render_panel

@click.command()
@click.argument('target')
def screenshot(target):
    """
    Take a screenshot of a target URL or file of URLs.
    """
    render_panel(f"[bold cyan]📸 Visual Recon[/bold cyan] - Target: [yellow]{target}[/yellow]", border_style="cyan")
    
    provider = GowitnessProvider()
    
    if not provider.is_available():
        render_outcome("Error: gowitness binary not found in tools/go/bin/", border_style="red")
        return

    render_panel("Starting capture...", border_style="cyan")
    output_path = provider.execute(target)
    
    if output_path:
        render_outcome(f"Success! Screenshots saved in: {output_path}")
    else:
        render_outcome("Failed to take screenshot.", border_style="red")

if __name__ == "__main__":
    screenshot()
