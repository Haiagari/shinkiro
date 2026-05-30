"""
Shared collaboration artifacts for multi-operator runs.

The goal is not live co-editing UI; it's a stable manifest and artifact
directory structure that multiple operators/jobs can coordinate against.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass
class CollaborationManifest:
    session_id: str
    target: str
    scan_id: int | None = None
    status: str = "shared"
    operators: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def collaboration_dir(session_id: str) -> Path:
    return Path("runs") / session_id


def collaboration_manifest_path(session_id: str) -> Path:
    return collaboration_dir(session_id) / "collaboration.json"


def write_collaboration_manifest(
    session_id: str,
    target: str,
    *,
    scan_id: int | None = None,
    operators: Iterable[str] | None = None,
    artifacts: Iterable[str] | None = None,
    status: str = "shared",
) -> dict[str, Any]:
    manifest = CollaborationManifest(
        session_id=session_id,
        target=target,
        scan_id=scan_id,
        status=status,
        operators=list(operators or []),
        artifacts=list(artifacts or []),
    )

    path = collaboration_manifest_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
    return manifest.to_dict()


def read_collaboration_manifest(session_id: str) -> dict[str, Any]:
    path = collaboration_manifest_path(session_id)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def append_collaboration_operator(session_id: str, operator: str) -> dict[str, Any]:
    manifest = read_collaboration_manifest(session_id)
    operators = manifest.get("operators", [])
    if operator not in operators:
        operators.append(operator)
    manifest["operators"] = operators
    manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
    path = collaboration_manifest_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, default=str) + "\n", encoding="utf-8")
    return manifest
