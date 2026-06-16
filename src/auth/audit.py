"""
Security Audit Logger - OzyRecon v8.1
Records every authenticated action with automatic log rotation.
"""

import logging
import json
import os
from datetime import datetime
from pathlib import Path
from fastapi import Request
from typing import Dict

logger = logging.getLogger("auth.audit")

class AuditLogger:
    MAX_BYTES = 50 * 1024 * 1024  # 50 MB antes de rotar
    BACKUP_COUNT = 5

    def __init__(self, log_path: str = "runs/audit_security.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._rotate_if_needed()

    def _rotate_if_needed(self):
        if not self.log_path.exists():
            return
        size = self.log_path.stat().st_size
        if size < self.MAX_BYTES:
            return
        for i in range(self.BACKUP_COUNT - 1, 0, -1):
            old = self.log_path.with_suffix(f".{i}.jsonl")
            new = self.log_path.with_suffix(f".{i + 1}.jsonl")
            if old.exists():
                os.rename(old, new) if i < self.BACKUP_COUNT else None
        os.rename(self.log_path, self.log_path.with_suffix(".1.jsonl"))

    def log_action(self, request: Request, key_data: Dict, scope: str = "unknown"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "key_name": key_data.get("name"),
            "ip": request.client.host if request.client else "unknown",
            "method": request.method,
            "endpoint": request.url.path,
            "scope_used": scope,
            "user_agent": request.headers.get("User-Agent")
        }
        
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

# Global Instance
audit_logger = AuditLogger()
