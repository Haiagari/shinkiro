"""
Bootstrap helpers for OzyRecon runtime files.

These helpers keep the project portable by seeding mutable runtime files from
tracked examples when they are missing.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from src.plugins.loader import plugin_loader


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _project_path(*parts: str, base_dir: Optional[Path] = None) -> Path:
    root = base_dir if base_dir is not None else PROJECT_ROOT
    return root.joinpath(*parts)


def _copy_if_missing(example_path: Path, target_path: Path) -> bool:
    if target_path.exists() or not example_path.exists():
        return False
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(example_path, target_path)
    return True


def ensure_config_file(target_path: Optional[Path] = None, base_dir: Optional[Path] = None) -> bool:
    """Seeds config/config.yaml from config/config.example.yaml when missing."""
    if target_path is None:
        target_path = _project_path("config", "config.yaml", base_dir=base_dir)
    return _copy_if_missing(
        target_path.with_name("config.example.yaml"),
        target_path,
    )


def ensure_api_key_registry(target_path: Optional[Path] = None, base_dir: Optional[Path] = None) -> bool:
    """
    Seeds config/api_keys.json from config/api_keys.example.json when missing.

    If no example exists, writes an empty registry so the project can still
    create keys at runtime.
    """
    if target_path is None:
        target_path = _project_path("config", "api_keys.json", base_dir=base_dir)
    if target_path.exists():
        return False

    example_path = target_path.with_name("api_keys.example.json")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if example_path.exists():
        shutil.copy2(example_path, target_path)
    else:
        target_path.write_text(
            json.dumps(
                {
                    "keys": [],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            )
        )
    return True


def ensure_evidence_private_key(target_path: Optional[Path] = None, base_dir: Optional[Path] = None) -> bool:
    """Creates the Ed25519 evidence key if it does not already exist."""
    if target_path is None:
        target_path = _project_path("resources", "keys", "evidence_key.priv", base_dir=base_dir)
    if target_path.exists():
        return False

    target_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    target_path.write_bytes(private_key.private_bytes_raw())
    return True


def bootstrap_runtime_files(base_dir: Optional[Path] = None) -> dict[str, bool]:
    """
    Ensures mutable runtime files exist, seeding them from tracked examples.
    """
    # Ensure runtime directories exist (v8.3.2)
    for d in ["evidence", "runs", "runtime", "exports"]:
        dir_path = _project_path(d, base_dir=base_dir)
        dir_path.mkdir(parents=True, exist_ok=True)

    plugin_loader.discover(["plugins"])

    return {
        "config": ensure_config_file(base_dir=base_dir),
        "api_keys": ensure_api_key_registry(base_dir=base_dir),
        "evidence_key": ensure_evidence_private_key(base_dir=base_dir),
    }
