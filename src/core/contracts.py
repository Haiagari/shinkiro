"""
Runtime contract constants for OzyRecon.

These values define the stable shape that the local engine exposes.
"""

from typing import Dict, Iterable, Tuple

CONTRACT_VERSION = "scan-result.v1"

MODE_ENVELOPE_FIELDS: Tuple[str, ...] = (
    "status",
    "session_id",
    "target",
    "mode",
    "contract_version",
    "result",
    "observability",
)

SESSION_TRACE_FIELDS: Tuple[str, ...] = (
    "session_id",
    "target",
    "mode",
    "scan",
    "session",
    "workflow_steps",
    "evidence",
    "decisions",
    "summary",
)

SCAN_RESULT_FIELDS: Tuple[str, ...] = (
    "type",
    "source",
    "version",
    "contract_version",
    "session_id",
    "target",
    "mode",
    "timestamp",
    "started_at",
    "ended_at",
    "duration_seconds",
    "assets",
    "services",
    "findings",
    "diff",
    "stats",
    "config",
    "errors",
)


def missing_fields(payload: Dict[str, object], required: Iterable[str]) -> list[str]:
    """Return required fields that are missing from a payload."""
    return [field for field in required if field not in payload]


def validate_required_fields(payload: Dict[str, object], required: Iterable[str]) -> None:
    """Raise if a payload is missing required contract fields."""
    missing = missing_fields(payload, required)
    if missing:
        raise ValueError(f"Missing contract fields: {', '.join(missing)}")
