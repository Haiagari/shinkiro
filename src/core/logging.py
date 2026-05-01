"""
Logging Estructurado para OzyRecon
Provee logging con diferentes niveles y salida a archivos.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console


class OzyLogger:
    """Logger estructurado para OzyRecon."""
    
    _loggers = {}
    
    def __init__(self, name: str, log_dir: Optional[Path] = None):
        self.name = name
        self.log_dir = log_dir or self._get_default_log_dir()
        self.logger = self._setup_logger(name)
    
    @staticmethod
    def _get_default_log_dir() -> Path:
        """Obtiene el directorio de logs por defecto."""
        env_dir = os.getenv("OZY_LOG_DIR")
        if env_dir:
            return Path(env_dir).expanduser()

        state_dir = os.getenv("OZY_STATE_DIR")
        if state_dir:
            return Path(state_dir).expanduser() / "logs"

        xdg_state_home = os.getenv("XDG_STATE_HOME")
        if xdg_state_home:
            return Path(xdg_state_home).expanduser() / "OzyRecon" / "logs"

        return Path.home() / ".local" / "state" / "OzyRecon" / "logs"
    
    def _setup_logger(self, name: str) -> logging.Logger:
        """Configura el logger con handlers de consola y archivo."""
        if name in self._loggers:
            return self._loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers = []  # Limpiar handlers existentes
        
        # Formato estructurado
        fmt = '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
        datefmt = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt)
        
        # Handler de consola
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        logger.addHandler(console)
        
        # Handler de archivo
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_file = self.log_dir / f"{name}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            fallback_dir = Path("/tmp/OzyRecon/logs")
            fallback_dir.mkdir(parents=True, exist_ok=True)
            log_file = fallback_dir / f"{name}.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            self.log_dir = fallback_dir
        
        self._loggers[name] = logger
        
        # Integration with Ozy Platform Telemetry
        try:
            from src.core.platform_telemetry import setup_platform_logging
            setup_platform_logging()
        except ImportError:
            pass
            
        return logger
    
    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg, **kwargs)
    
    def info(self, msg: str, **kwargs):
        self.logger.info(msg, **kwargs)
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg, **kwargs)
    
    def error(self, msg: str, **kwargs):
        self.logger.error(msg, **kwargs)
    
    def critical(self, msg: str, **kwargs):
        self.logger.critical(msg, **kwargs)
    
    def exception(self, msg: str, **kwargs):
        self.logger.exception(msg, **kwargs)


# Loggers predefinidos para diferentes componentes
def get_logger(name: str) -> OzyLogger:
    """Factory de loggers."""
    return OzyLogger(name)


# Loggers de uso común
agent_logger = get_logger('agent')
scan_logger = get_logger('scan')
opsec_logger = get_logger('opsec')
recon_logger = get_logger('recon')
notification_logger = get_logger('notification')

# Rich console shared by operational modes that render live tables/panels.
console = Console()
