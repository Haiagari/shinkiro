"""Helpers for runtime session and autonomy payload assembly."""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.intelligence.autonomy.autonomy import AutonomyPlanner
from src.storage.queries import DBQueries


def build_session_trace_payload(db: Session, session_id: str) -> dict[str, object]:
    """Build the public /sessions/{session_id}/trace response payload."""
    return DBQueries(db).get_session_trace(session_id)


def build_session_analysis_payload(db: Session, session_id: str) -> dict[str, object]:
    """Build the public /sessions/{session_id}/analyze response payload."""
    trace = build_session_trace_payload(db, session_id)
    return {"session_id": session_id, "analysis": trace}


def build_autonomy_plan_payload(db: Session, target: str) -> dict[str, object]:
    """Build the public /autonomy/{target} response payload."""
    planner = AutonomyPlanner(db)
    plan = planner.build_plan(target)
    return plan.to_dict()


__all__ = [
    "build_autonomy_plan_payload",
    "build_session_analysis_payload",
    "build_session_trace_payload",
]
