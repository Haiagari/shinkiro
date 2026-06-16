"""
SessionManager - Ciclo de vida de sesiones de escaneo y persistencia.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.storage.models import Session as ScanSession, WorkflowStep
from src.storage.queries import DBQueries
from src.core.logging import get_logger

logger = get_logger("modes.session")


class SessionManager:
    """Manages scan session persistence and lifecycle in the database."""

    def __init__(self, db_session) -> None:
        self.db_session = db_session
        self.db = DBQueries(db_session)

    def ensure_runtime_scan(
        self,
        target: str,
        session_id: str,
        mode: str,
        started_at,
        options: Dict[str, Any],
    ):
        """Create or reuse the SQLAlchemy scan representing this execution."""
        existing = self.db.get_scan_by_session(session_id)
        if existing:
            return existing

        return self.db.create_scan(
            target,
            session_id,
            mode=mode,
            status="running",
            start_time=started_at,
            subdomains_found=0,
            hosts_alive=0,
            ports_found=0,
            findings=0,
            out_dir=options.get("output"),
        )

    def finalize_runtime_scan(
        self,
        runtime_scan,
        context,
        options: Dict[str, Any],
        status: str,
        error_summary: Optional[str] = None,
        exit_code: int = 0,
    ) -> None:
        """Update the persisted scan with the final execution state."""
        if runtime_scan is None:
            return

        scan_status = "completed" if status in {"success", "completed"} else "failed"
        self.db.update_scan_status(
            runtime_scan.id,
            scan_status,
            subdomains_found=context.subdomains_found,
            hosts_alive=context.hosts_alive,
            ports_found=context.ports_found,
            findings=context.findings,
            errors=error_summary,
            out_dir=options.get("output"),
        )

    def upsert_session_summary(
        self,
        session_id: str,
        target: str,
        mode: str,
        context,
        status: str,
        error_summary: Optional[str] = None,
        exit_code: int = 0,
    ) -> None:
        """Persist or update a session summary for trace reconstruction."""
        session = self.db_session.query(ScanSession).filter(
            ScanSession.session_id == session_id
        ).first()

        counts = {
            "subdomains": context.subdomains_found,
            "hosts": context.hosts_alive,
            "ports": context.ports_found,
            "findings": context.findings,
        }

        if not session:
            session = ScanSession(
                session_id=session_id,
                target=target,
                mode=mode,
                started_at=context.started_at,
                status=status,
                exit_code=exit_code,
                config_used={
                    "threads": context.threads,
                    "rate_limit": context.rate_limit,
                    "mode": mode,
                },
                **counts,
            )
            self.db_session.add(session)
        else:
            session.target = target
            session.mode = mode
            session.status = status
            session.exit_code = exit_code
            session.subdomains = counts["subdomains"]
            session.hosts = counts["hosts"]
            session.ports = counts["ports"]
            session.findings = counts["findings"]
            session.config_used = {
                "threads": context.threads,
                "rate_limit": context.rate_limit,
                "mode": mode,
            }

        if status in {"success", "failed"}:
            session.ended_at = context.finished_at or datetime.now(timezone.utc)
            if context.duration is not None:
                session.duration = context.duration
            session.error_summary = error_summary

        self.db_session.commit()

    def persist_workflow_history(self, target_name: str, context) -> None:
        """Dump the context timeline into the database as workflow steps."""
        target_obj = self.db.get_target(target_name)
        target_id = target_obj.id if target_obj else None

        for event in context.timeline:
            step = WorkflowStep(
                target_id=target_id,
                state=event.get("stage", "unknown").upper(),
                timestamp=datetime.fromisoformat(event["timestamp"]),
                actor="SYSTEM",
                notes=json.dumps({
                    "message": event.get("message"),
                    "data": event.get("data", {}),
                }),
            )
            self.db_session.add(step)

        try:
            self.db_session.commit()
        except Exception as e:
            logger.warning("Failed to persist workflow history: %s", e)
