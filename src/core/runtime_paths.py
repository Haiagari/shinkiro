"""
Runtime path helpers for PromptWall.

Keeps mutable state outside the repository tree unless a caller explicitly
overrides it with environment variables.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def _is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def get_runtime_root() -> Path:
    env_dir = os.getenv("OZY_RUNTIME_DIR")
    if env_dir:
        return Path(env_dir).expanduser()

    state_dir = os.getenv("OZY_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser()

    xdg_state_home = os.getenv("XDG_STATE_HOME")
    if xdg_state_home:
        candidate = Path(xdg_state_home).expanduser() / "PromptWall"
        if _is_writable(candidate.parent):
            return candidate

    home_candidate = Path.home() / ".local" / "state" / "PromptWall"
    if _is_writable(home_candidate.parent):
        return home_candidate

    return Path("/tmp") / "PromptWall"


def get_temp_dir() -> Path:
    env_dir = os.getenv("OZY_TEMP_DIR")
    if env_dir:
        return Path(env_dir).expanduser()
    return get_runtime_root() / "temp"


def get_config_dir() -> Path:
    env_dir = os.getenv("OZY_CONFIG_DIR")
    if env_dir:
        return Path(env_dir).expanduser()
    return get_runtime_root() / "config"


def get_export_dir(*parts: str) -> Path:
    return get_runtime_root() / "exports" / Path(*parts)


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "target"
