"""
CLI Command: serve - Start the PromptWall API server.
"""

import click
import threading
import time

from cli.shared import console, ensure_config_loaded, render_outcome, render_plan, render_stage


def _serve_plan(host: str, port: int, scheduler: bool, interval: int) -> None:
    lines = [
        f"[bold]Host:[/bold] {host}",
        f"[bold]Port:[/bold] {port}",
        f"[bold]Scheduler:[/bold] {'enabled' if scheduler else 'disabled'}",
        f"[bold]Worker interval:[/bold] {interval}s",
        "",
        "[bold]Pipeline:[/bold]",
        "  1. Boot API runtime",
        "  2. Expose health and runtime endpoints",
        "  3. Start optional scheduler worker",
        "  4. Keep server alive until interrupted",
    ]
    render_plan("PromptWall Serve", lines, border_style="bright_cyan")


@click.command(name="serve")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--scheduler/--no-scheduler", default=False, help="Also run the scheduler worker")
@click.option("--interval", default=60, type=int, help="Scheduler check interval in seconds")
@ensure_config_loaded()
def serve(host: str, port: int, scheduler: bool, interval: int):
    """
    Start the PromptWall API server.
    
    Exposes endpoints for:
    - /targets - List all targets
    - /sessions - List all sessions  
    - /hunt - Trigger a new hunt
    - /diff - Compare scans
    - /schedule - Manage scheduled tasks
    
    Use --scheduler to also run the background scheduler worker.
    """
    _serve_plan(host, port, scheduler, interval)
    render_stage("1/4", "Boot API runtime", f"Preparing PromptWall API on {host}:{port}.")
    
    if scheduler:
        render_stage("2/4", "Start scheduler", f"Launching background worker with {interval}s interval.", border_style="yellow")
        scheduler_thread = _SchedulerWorker(interval)
        scheduler_thread.start()
    else:
        render_stage("2/4", "Start scheduler", "Scheduler worker disabled for this run.", border_style="cyan")
    
    try:
        from src.core.api import start_api
        render_stage("3/4", "Serve API", "Starting FastAPI/uvicorn runtime and exposing endpoints.", border_style="green")
        start_api(host=host, port=port)
    except KeyboardInterrupt:
        render_outcome("Server stopped.", border_style="yellow")


class _SchedulerWorker(threading.Thread):
    """Background worker that runs scheduled tasks."""
    
    def __init__(self, interval: int = 60):
        super().__init__(daemon=True)
        self.interval = interval
        self.running = True
    
    def run(self):
        from src.scheduler import Scheduler
        
        render_stage("worker", "Scheduler loop", "Background task polling is active.", border_style="cyan")
        while self.running:
            try:
                scheduler = Scheduler()
                pending = scheduler.get_pending_tasks()
                
                if pending:
                    render_stage("worker", "Pending tasks", f"{len(pending)} task(s) ready for execution.", border_style="yellow")
                for task in pending:
                    render_stage("worker", "Run task", f"Executing scheduled task {task.id}.")
                    result = scheduler.run_task(task.id)
                    
                    if result["status"] == "success":
                        render_outcome(f"Task {task.id} completed")
                    else:
                        render_outcome(f"Task {task.id} failed", border_style="red")
                         
            except Exception as e:
                render_outcome(f"Scheduler error: {e}", border_style="red")
            
            time.sleep(self.interval)
    
    def stop(self):
        self.running = False


__all__ = ["serve"]
