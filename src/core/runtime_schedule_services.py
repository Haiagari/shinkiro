"""Helpers for runtime schedule payload assembly."""

from __future__ import annotations

from typing import Any

from src.scheduler import Scheduler


def list_schedule_tasks_payload() -> dict[str, list[dict[str, Any]]]:
    """Build the public /schedule/tasks GET response payload."""
    scheduler = Scheduler()
    tasks = scheduler.list_tasks()
    return {
        "tasks": [
            {
                "id": task.id,
                "target": task.target,
                "profile": task.profile,
                "interval_hours": task.interval_hours,
                "enabled": task.enabled,
                "last_run": task.last_run,
                "next_run": task.next_run,
            }
            for task in tasks
        ]
    }


def add_schedule_task_payload(
    target: str,
    profile: str = "safe-active",
    interval_hours: int = 24,
) -> dict[str, Any]:
    """Build the public /schedule/tasks POST response payload."""
    scheduler = Scheduler()
    task = scheduler.add_task(target, profile=profile, interval_hours=interval_hours)
    return {
        "status": "created",
        "task": {
            "id": task.id,
            "target": task.target,
            "profile": task.profile,
            "interval_hours": task.interval_hours,
        },
    }


def run_schedule_task_payload(task_id: str) -> dict[str, Any]:
    """Build the public /schedule/tasks/{task_id}/run response payload."""
    scheduler = Scheduler()
    return scheduler.run_task(task_id)


__all__ = [
    "add_schedule_task_payload",
    "list_schedule_tasks_payload",
    "run_schedule_task_payload",
]
