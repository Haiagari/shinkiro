"""Helpers for runtime hunt payload assembly."""

from __future__ import annotations

from typing import Any

from src.security.target_validator import is_safe_target


def build_hunt_response_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Build the public /hunt response payload."""
    target = (payload or {}).get("target")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")

    is_safe, reason = is_safe_target(target)
    if not is_safe:
        raise ValueError(reason)

    return {
        "status": "accepted",
        "target": target.strip(),
        "dry_run": bool((payload or {}).get("dry_run", False)),
    }


__all__ = ["build_hunt_response_payload"]
