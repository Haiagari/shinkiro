"""
Structured Logging for PromptWall v8.3.2
Provides JSONL structured logs with rotation and secret scrubbing.
"""

import logging
import os
import sys
import json
import re
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler
from rich.console import Console

class JSONFormatter(logging.Formatter):
    """Formats log records as structured JSON and scrubs secrets."""
    def format(self, record):
        message = record.getMessage()
        # Log Scrubbing: Redact API keys and Auth headers
        scrubbed_message = re.sub(r"(ozy_[a-z0-9_]+|[A-Za-z0-9+/]{32,})", "[REDACTED]", message)
        
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": scrubbed_message,
            "module": record.module,
            "func": record.funcName
        }
        if hasattr(record, "session_id"):
            log_entry["session_id"] = record.session_id
        return json.dumps(log_entry)

class OzyLogger:
    """Structured logger for PromptWall."""
    
    _loggers = {}
    
    def __init__(self, name: str, log_dir: Optional[Path] = None):
        self.name = name
        self.log_dir = log_dir or self._get_default_log_dir()
        self.logger = self._setup_logger(name)
    
    @staticmethod
    def _get_default_log_dir() -> Path:
        """Default directory for logs."""
        env_dir = os.getenv("OZY_LOG_DIR")
        if env_dir:
            return Path(env_dir).expanduser()
        
        home_candidate = Path.home() / ".local" / "state" / "PromptWall" / "logs"
        return home_candidate

    def _setup_logger(self, name: str) -> logging.Logger:
        """Configures logger with console and rotating file handlers."""
        if name in self._loggers:
            return self._loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers = []
        
        fmt = '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
        datefmt = '%Y-%m-%d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt)
        
        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Rotating File Handlers (JSONL and Plain Text)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            
            # JSONL Handler
            json_file = self.log_dir / f"{name}.jsonl"
            json_handler = RotatingFileHandler(json_file, maxBytes=100*1024*1024, backupCount=5)
            json_handler.setFormatter(JSONFormatter(datefmt=datefmt))
            logger.addHandler(json_handler)
            
            # Plain Text Handler
            txt_file = self.log_dir / f"{name}.log"
            txt_handler = RotatingFileHandler(txt_file, maxBytes=100*1024*1024, backupCount=5)
            txt_handler.setFormatter(formatter)
            logger.addHandler(txt_handler)
            
        except Exception:
            # Fallback to tmp
            pass
            
        self._loggers[name] = logger
        return logger

    def debug(self, msg, **kwargs): self.logger.debug(msg, **kwargs)
    def info(self, msg, **kwargs): self.logger.info(msg, **kwargs)
    def warning(self, msg, **kwargs): self.logger.warning(msg, **kwargs)
    def error(self, msg, **kwargs): self.logger.error(msg, **kwargs)
    def critical(self, msg, **kwargs): self.logger.critical(msg, **kwargs)
    def exception(self, msg, **kwargs): self.logger.exception(msg, **kwargs)

def get_logger(name: str) -> OzyLogger:
    return OzyLogger(name)

agent_logger = get_logger('agent')
scan_logger = get_logger('scan')
opsec_logger = get_logger('opsec')
recon_logger = get_logger('recon')
notification_logger = get_logger('notification')

console = Console()
