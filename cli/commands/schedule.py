"""
CLI Command: schedule - Manage scheduled scans.
"""

import click
from rich.table import Table

from cli.shared import console, ensure_config_loaded, render_outcome, render_panel, render_plan, render_stage
from src.scheduler import Scheduler, init_scheduler_config


def _schedule_plan(action: str, target: str | None = None, profile: str | None = None, interval: int | None = None) -> None:
    lines = [
        f"[bold]Action:[/bold] {action}",
        f"[bold]Target:[/bold] {target or '-'}",
        f"[bold]Profile:[/bold] {profile or '-'}",
        f"[bold]Interval:[/bold] {f'{interval}h' if interval is not None else '-'}",
        "",
        "[bold]Pipeline:[/bold]",
        "  1. Load scheduler config",
        "  2. Resolve tasks",
        "  3. Apply requested change",
        "  4. Confirm next run or state",
    ]
    render_plan("OzyRecon Schedule", lines, border_style="bright_blue")


def _schedule_stage(step: str, title: str, detail: str, border_style: str = "cyan") -> None:
    render_stage(step, title, detail, border_style=border_style)


@click.group(name="schedule")
def schedule():
    """Manage scheduled reconnaissance scans."""
    pass


@schedule.command(name="list")
@ensure_config_loaded()
def schedule_list():
    """List all scheduled tasks."""
    _schedule_plan("list")
    _schedule_stage("1/4", "Load config", "Initializing scheduler configuration and reading tasks.")
    init_scheduler_config()
    scheduler = Scheduler()
    tasks = scheduler.list_tasks()
    
    if not tasks:
        render_outcome("No scheduled tasks. Add one with: ozy schedule add <target>", border_style="yellow")
        return

    _schedule_stage("2/4", "Render table", f"Preparing {len(tasks)} scheduled task(s) for display.")
    
    table = Table(title="Scheduled Tasks", border_style="blue")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Profile", style="magenta")
    table.add_column("Interval", style="yellow")
    table.add_column("Enabled", justify="center")
    table.add_column("Last Run", style="dim")
    table.add_column("Next Run", style="green")
    
    for task in tasks:
        enabled = "[green]✓[/green]" if task.enabled else "[red]✗[/red]"
        table.add_row(
            task.id,
            task.target,
            task.profile,
            f"{task.interval_hours}h",
            enabled,
            task.last_run or "-",
            task.next_run or "-",
        )

    console.print(table)
    render_outcome("Schedule list ready.")


@schedule.command(name="add")
@click.argument("target")
@click.option("--profile", default="safe-active", type=click.Choice(["passive", "safe-active", "authorized"]), help="Scan profile")
@click.option("--interval", default=24, type=int, help="Interval in hours")
@ensure_config_loaded()
def schedule_add(target: str, profile: str, interval: int):
    """Add a scheduled scan for TARGET."""
    _schedule_plan("add", target=target, profile=profile, interval=interval)
    _schedule_stage("1/4", "Load config", "Initializing scheduler configuration.")
    init_scheduler_config()
    scheduler = Scheduler()
    
    _schedule_stage("2/4", "Register task", f"Creating a recurring scan for {target}.")
    task = scheduler.add_task(target, profile=profile, interval_hours=interval)
    
    _schedule_stage("3/4", "Confirm scheduling", f"Profile {profile} will run every {interval}h.", border_style="green")
    render_outcome(f"Scheduled task added for {target}")
    render_panel(f"[dim]Profile: {profile}, Interval: {interval}h[/dim]", border_style="green")


@schedule.command(name="remove")
@click.argument("task_id")
@ensure_config_loaded()
def schedule_remove(task_id: str):
    """Remove a scheduled task by ID."""
    _schedule_plan("remove", target=task_id)
    _schedule_stage("1/3", "Load task", f"Resolving task {task_id}.")
    scheduler = Scheduler()
    
    _schedule_stage("2/3", "Apply change", "Removing the task from the schedule.")
    if scheduler.remove_task(task_id):
        _schedule_stage("3/3", "Confirm removal", f"Task {task_id} is no longer scheduled.", border_style="green")
        render_outcome(f"Task {task_id} removed")
    else:
        _schedule_stage("3/3", "Removal failed", f"Task {task_id} was not found.", border_style="red")
        render_outcome(f"Task {task_id} not found", border_style="red")


@schedule.command(name="run")
@click.argument("task_id")
@ensure_config_loaded()
def schedule_run(task_id: str):
    """Run a scheduled task immediately."""
    _schedule_plan("run", target=task_id)
    _schedule_stage("1/3", "Load task", f"Preparing task {task_id} for immediate execution.")
    scheduler = Scheduler()
    
    _schedule_stage("2/3", "Execute task", "Running the scheduled scan now.")
    result = scheduler.run_task(task_id)
    
    if result["status"] == "success":
        _schedule_stage("3/3", "Execution complete", f"Task {task_id} completed successfully.", border_style="green")
        render_outcome(f"Task {task_id} completed")
    elif result["status"] == "skipped":
        _schedule_stage("3/3", "Execution skipped", f"Task {task_id} is disabled.", border_style="yellow")
        render_outcome(f"Task {task_id} is disabled", border_style="yellow")
    else:
        _schedule_stage("3/3", "Execution failed", f"Task {task_id} returned an error.", border_style="red")
        render_outcome(f"Task {task_id} failed: {result.get('error')}", border_style="red")


@schedule.command(name="pending")
@ensure_config_loaded()
def schedule_pending():
    """Show tasks that are due to run."""
    _schedule_plan("pending")
    _schedule_stage("1/3", "Load queue", "Checking tasks due to run.")
    scheduler = Scheduler()
    tasks = scheduler.get_pending_tasks()
    
    if not tasks:
        render_outcome("No pending tasks.")
        return
    
    _schedule_stage("2/3", "Format queue", f"Found {len(tasks)} pending task(s).", border_style="green")
    render_panel(f"[bold cyan]Pending Tasks ({len(tasks)}):[/bold cyan]", border_style="cyan")
    for task in tasks:
        console.print(f"  • {task.target} ({task.profile})")
    render_outcome("Pending queue ready.")


__all__ = ["schedule"]
