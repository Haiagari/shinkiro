"""
PromptWall Core Module
Provee configuración, logging, errores y contexto global.
"""

from .config import config, Config
from .logging import get_logger, OzyLogger, agent_logger, scan_logger, opsec_logger, recon_logger
from .errors import (
    PromptWallError,
    ConfigError,
    TargetError,
    ScanError,
    OPSECError,
    StorageError,
    ToolError,
    ExportError,
    NotificationError,
    AIError,
)
__all__ = [
    # Config
    'config',
    'Config',
    # Logging
    'get_logger',
    'OzyLogger',
    'agent_logger',
    'scan_logger',
    'opsec_logger',
    'recon_logger',
    # Errors
    'PromptWallError',
    'ConfigError',
    'TargetError',
    'ScanError',
    'OPSECError',
    'StorageError',
    'ToolError',
    'ExportError',
    'NotificationError',
    'AIError',
]