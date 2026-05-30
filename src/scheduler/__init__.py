"""
OzyRecon Scheduler - Scheduled and recurring scans.
Enables periodic attack surface monitoring.
"""

import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Optional
from pathlib import Path

import yaml

from src.core.logging import get_logger

logger = get_logger("scheduler")


@dataclass
class ScheduledTask:
    """A scheduled scan task."""
    id: str
    target: str
    profile: str = "safe-active"
    interval_hours: int = 24
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consecutive_failures: int = 0


class Scheduler:
    """
    Scheduler for recurring reconnaissance scans.
    
    Manages scheduled tasks in config/scheduler.yaml and executes
    scans at configured intervals for attack surface monitoring.
    """
    
    def __init__(self, config_path: str = "config/scheduler.yaml"):
        self.config_path = Path(config_path)
        self.tasks: list[ScheduledTask] = []
        self._load_tasks()
    
    def _load_tasks(self) -> None:
        """Load scheduled tasks from config file."""
        if not self.config_path.exists():
            self.tasks = []
            return
        
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            
            self.tasks = [
                ScheduledTask(
                    id=task["id"],
                    target=task["target"],
                    profile=task.get("profile", "safe-active"),
                    interval_hours=task.get("interval_hours", 24),
                    enabled=task.get("enabled", True),
                    last_run=task.get("last_run"),
                    next_run=task.get("next_run"),
                    created_at=task.get("created_at", datetime.now(timezone.utc).isoformat()),
                    consecutive_failures=task.get("consecutive_failures", 0),
                )
                for task in data.get("tasks", [])
            ]
            logger.info(f"Loaded {len(self.tasks)} scheduled tasks")
        except Exception as e:
            logger.warning(f"Failed to load scheduler config: {e}")
            self.tasks = []
    
    def _save_tasks(self) -> None:
        """Save scheduled tasks to config file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "tasks": [
                {
                    "id": task.id,
                    "target": task.target,
                    "profile": task.profile,
                    "interval_hours": task.interval_hours,
                    "enabled": task.enabled,
                    "last_run": task.last_run,
                    "next_run": task.next_run,
                    "created_at": task.created_at,
                    "consecutive_failures": task.consecutive_failures,
                }
                for task in self.tasks
            ]
        }
        
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)
    
    def add_task(
        self,
        target: str,
        profile: str = "safe-active",
        interval_hours: int = 24,
    ) -> ScheduledTask:
        """Add a new scheduled task."""
        task_id = f"task_{target}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        
        task = ScheduledTask(
            id=task_id,
            target=target,
            profile=profile,
            interval_hours=interval_hours,
            enabled=True,
        )
        
        self.tasks.append(task)
        self._save_tasks()
        
        logger.info(f"Added scheduled task {task_id} for {target}")
        return task
    
    def remove_task(self, task_id: str) -> bool:
        """Remove a scheduled task by ID."""
        initial_len = len(self.tasks)
        self.tasks = [t for t in self.tasks if t.id != task_id]
        
        if len(self.tasks) < initial_len:
            self._save_tasks()
            logger.info(f"Removed scheduled task {task_id}")
            return True
        return False
    
    def list_tasks(self) -> list[ScheduledTask]:
        """List all scheduled tasks."""
        return self.tasks
    
    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Get a specific task by ID."""
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None
    
    def get_pending_tasks(self) -> list[ScheduledTask]:
        """Get tasks that are due to run."""
        now = datetime.now(timezone.utc)
        pending = []
        
        for task in self.tasks:
            if not task.enabled:
                continue
            
            if task.next_run:
                next_dt = datetime.fromisoformat(task.next_run.replace("Z", "+00:00"))
                if next_dt <= now:
                    pending.append(task)
            elif not task.last_run:
                pending.append(task)
        
        return pending
    
    def run_task(self, task_id: str) -> dict[str, Any]:
        """Execute a scheduled task."""
        task = self.get_task(task_id)
        if not task:
            return {"status": "error", "message": f"Task {task_id} not found"}
        
        if not task.enabled:
            return {"status": "skipped", "message": "Task is disabled"}
        
        logger.info(f"Running scheduled task {task.id} for {task.target}")
        
        try:
            from src.modes.hunt import HuntMode
            
            mode = HuntMode(task.target, options={"profile": task.profile})
            result = mode.run()
            
            now = datetime.now(timezone.utc).isoformat()
            task.last_run = now
            
            next_dt = datetime.now(timezone.utc)
            from datetime import timedelta
            next_dt = next_dt + timedelta(hours=task.interval_hours)
            task.next_run = next_dt.isoformat()
            task.consecutive_failures = 0
            
            self._save_tasks()
            
            return {
                "status": "success",
                "task_id": task.id,
                "target": task.target,
                "result": result,
                "completed_at": now,
            }
            
        except Exception as e:
            task.consecutive_failures += 1
            logger.error(f"Scheduled task {task.id} failed: {e}")
            self._save_tasks()
            
            return {
                "status": "error",
                "task_id": task.id,
                "error": str(e),
            }


def init_scheduler_config() -> None:
    """Initialize scheduler config file if it doesn't exist."""
    config_path = Path("config/scheduler.yaml")
    
    if config_path.exists():
        return
    
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    template = """# OzyRecon Scheduler Configuration
# Defines scheduled and recurring reconnaissance scans

tasks: []
# Example task:
# - id: task_example_com
#   target: example.com
#   profile: safe-active
#   interval_hours: 24
#   enabled: true

"""
    config_path.write_text(template, encoding="utf-8")
    logger.info(f"Created scheduler config at {config_path}")


__all__ = ["Scheduler", "ScheduledTask", "init_scheduler_config"]