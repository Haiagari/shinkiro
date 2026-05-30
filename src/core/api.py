"""
Local runtime API helpers for OzyRecon.

This module provides the minimal contract used by runtime tests and local
inspection flows without standing up the HTTP API server.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, status

from src.storage.database import SessionLocal
from src.core.runtime_views import build_sessions_payload, build_targets_payload
from src.core.scan_payloads import build_latest_scan_payload
from src.core.runtime_analytics import build_diff_payload, build_intelligence_graph_payload
from src.core.runtime_hunt import build_hunt_response_payload
from src.core.runtime_schedule_services import (
    add_schedule_task_payload,
    list_schedule_tasks_payload,
    run_schedule_task_payload,
)
from src.core.runtime_session_services import (
    build_autonomy_plan_payload,
    build_session_analysis_payload,
    build_session_trace_payload,
)


app = FastAPI(title="OzyRecon", version="9.0.1")

_MASTER_KEYS = {
    "ozy-admin-master-777",
    "master-admin",
    "master-admin-key",
    "auditor-externo",
}


def _require_api_key(x_api_key: Optional[str]) -> None:
    if not x_api_key or x_api_key not in _MASTER_KEYS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")


@app.get("/")
def root() -> Dict[str, Any]:
    return {"name": "OzyRecon", "version": app.version}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "contract": "ozy.runtime.v1",
        "metrics": {"scans_total": 0, "scans_failed": 0, "active_concurrency": 0},
    }


@app.get("/targets")
def list_targets(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> list[dict[str, object]]:
    _require_api_key(x_api_key)
    db = SessionLocal()
    try:
        return build_targets_payload(db)
    finally:
        db.close()


@app.get("/sessions")
def list_sessions(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> list[dict[str, object]]:
    _require_api_key(x_api_key)
    db = SessionLocal()
    try:
        return build_sessions_payload(db)
    finally:
        db.close()


@app.get("/intelligence/graph")
def intelligence_graph(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> Dict[str, Any]:
    _require_api_key(x_api_key)
    db = SessionLocal()
    try:
        return build_intelligence_graph_payload(db)
    finally:
        db.close()


@app.post("/hunt")
def hunt(
    payload: Dict[str, Any], x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")
) -> Dict[str, Any]:
    _require_api_key(x_api_key)
    try:
        return build_hunt_response_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@app.get("/sessions/{session_id}/trace")
def session_trace(
    session_id: str, x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")
) -> Dict[str, Any]:
    _require_api_key(x_api_key)
    return get_session_trace(session_id)


@app.get("/sessions/{session_id}/analyze")
def session_analyze(
    session_id: str, x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")
) -> Dict[str, Any]:
    _require_api_key(x_api_key)
    db = SessionLocal()
    try:
        return build_session_analysis_payload(db, session_id)
    finally:
        db.close()


@app.get("/autonomy/{target}")
def autonomy_plan(
    target: str, x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")
) -> Dict[str, Any]:
    _require_api_key(x_api_key)
    return get_autonomy_plan(target)


@app.get("/diff/{target}")
def diff_scans(
    target: str,
    scan_id: Optional[int] = None,
    previous_scan_id: Optional[int] = None,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> Dict[str, Any]:
    """Compare two scans for a target to detect changes."""
    _require_api_key(x_api_key)

    db = SessionLocal()
    try:
        return build_diff_payload(db, target, scan_id, previous_scan_id)
    finally:
        db.close()


@app.get("/schedule/tasks")
def list_schedule_tasks(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> Dict[str, Any]:
    """List all scheduled tasks."""
    _require_api_key(x_api_key)
    return list_schedule_tasks_payload()


@app.post("/schedule/tasks")
def add_schedule_task(
    target: str,
    profile: str = "safe-active",
    interval_hours: int = 24,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY"),
) -> Dict[str, Any]:
    """Add a new scheduled task."""
    _require_api_key(x_api_key)
    return add_schedule_task_payload(target, profile=profile, interval_hours=interval_hours)


@app.post("/schedule/tasks/{task_id}/run")
def run_schedule_task(
    task_id: str, x_api_key: Optional[str] = Header(default=None, alias="X-API-KEY")
) -> Dict[str, Any]:
    """Run a scheduled task immediately."""
    _require_api_key(x_api_key)
    return run_schedule_task_payload(task_id)


def get_latest_scan(target_domain: str) -> Dict[str, Any]:
    """Return the normalized latest scan payload for a target."""
    db = SessionLocal()
    try:
        return build_latest_scan_payload(db, target_domain)
    finally:
        db.close()


def get_session_trace(session_id: str) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        return build_session_trace_payload(db, session_id)
    finally:
        db.close()


def get_autonomy_plan(target: str) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        try:
            return build_autonomy_plan_payload(db, target)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    finally:
        db.close()


def start_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


__all__ = ["app", "get_latest_scan", "get_session_trace", "get_autonomy_plan", "start_api"]
