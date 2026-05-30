"""Helpers for runtime list payload assembly."""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.storage.models import Session as ScanSession
from src.storage.models import Target


def build_targets_payload(db: Session) -> list[dict[str, object]]:
    """Build the public /targets response payload."""
    rows = db.query(Target).order_by(Target.added_at.desc()).all()
    return [
        {
            "domain": row.domain,
            "in_scope": bool(row.in_scope),
            "priority": row.priority,
            "technologies": row.technologies or [],
        }
        for row in rows
    ]


def build_sessions_payload(db: Session) -> list[dict[str, object]]:
    """Build the public /sessions response payload."""
    rows = db.query(ScanSession).order_by(ScanSession.started_at.desc()).all()
    return [
        {
            "session_id": row.session_id,
            "target": row.target,
            "mode": row.mode,
            "status": row.status,
            "exit_code": row.exit_code,
        }
        for row in rows
    ]


__all__ = ["build_targets_payload", "build_sessions_payload"]
