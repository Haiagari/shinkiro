"""
CLI Command: serve - Start the PromptWall API server.
"""

import click

from cli.shared import ensure_config_loaded, render_outcome, render_plan, render_stage


def _serve_plan(host: str, port: int) -> None:
    lines = [
        f"[bold]Host:[/bold] {host}",
        f"[bold]Port:[/bold] {port}",
        "",
        "[bold]Pipeline:[/bold]",
        "  1. Boot API runtime",
        "  2. Expose health endpoint",
        "  3. Keep server alive until interrupted",
    ]
    render_plan("PromptWall Serve", lines, border_style="bright_cyan")


@click.command(name="serve")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@ensure_config_loaded()
def serve(host: str, port: int):
    """
    Start the PromptWall API server.

    Exposes the health endpoint and (from slice 2 on) the proxy surface.
    The v9 scheduler worker was removed with the recon stack.
    """
    _serve_plan(host, port)
    render_stage("1/2", "Boot API runtime", f"Preparing PromptWall API on {host}:{port}.")

    try:
        from src.core.api import start_api

        render_stage("2/2", "Serve API", "Starting FastAPI/uvicorn runtime.", border_style="green")
        start_api(host=host, port=port)
    except KeyboardInterrupt:
        render_outcome("Server stopped.", border_style="yellow")


__all__ = ["serve"]
