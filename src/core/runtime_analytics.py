"""Helpers for runtime intelligence and diff payload assembly."""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy.orm import Session

from src.intelligence.graph_builder import graph_builder
from src.storage.diff import DiffEngine
from src.storage.models import Scan, Target
from src.core.target_normalizer import normalize_lookup_target


def build_intelligence_graph_payload(db: Session) -> dict[str, Any]:
    """Build the public /intelligence/graph response payload."""
    latest = db.query(Scan).order_by(Scan.id.desc()).first()
    if not latest:
        return {
            "nodes": [],
            "edges": [],
            "metadata": {
                "total_nodes_detected": 0,
                "nodes_returned": 0,
                "schema_version": "1.2",
            },
        }
    return graph_builder.build_scan_graph(db, cast(int, latest.id))


def build_diff_payload(
    db: Session,
    target: str,
    scan_id: int | None = None,
    previous_scan_id: int | None = None,
) -> dict[str, Any]:
    """Build the public /diff/{target} response payload."""
    target_obj = db.query(Target).filter(Target.domain == normalize_lookup_target(target)).first()
    if not target_obj:
        return {"error": f"Target '{target}' not found"}

    current_scan = (
        db.query(Scan).filter(Scan.id == scan_id, Scan.target_id == target_obj.id).first()
        if scan_id
        else db.query(Scan)
        .filter(Scan.target_id == target_obj.id, Scan.status == "completed")
        .order_by(Scan.id.desc())
        .first()
    )
    if not current_scan:
        return {"error": "No completed scans found"}

    diff_report = DiffEngine(db).get_diff(normalize_lookup_target(target), cast(int, current_scan.id), previous_scan_id)
    return diff_report.to_dict()


__all__ = ["build_diff_payload", "build_intelligence_graph_payload"]
