"""
Security Audit Logger - OzyRecon v8.1
Records every authenticated action.
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from fastapi import Request
from typing import Dict

logger = logging.getLogger("auth.audit")

class AuditLogger:
    def __init__(self, log_path: str = "runs/audit_security.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

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
        
        # Append to JSONL (JSON Lines) for easy ingestion
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

# Global Instance
audit_logger = AuditLogger()
