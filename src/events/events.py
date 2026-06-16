from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict
from uuid import uuid4


@dataclass
class DomainEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)


class AssetDiscovered(DomainEvent):
    def __init__(self, domain: str, ip: str = None, technologies: list = None):
        super().__init__(event_type="asset_discovered", payload={
            "domain": domain, "ip": ip, "technologies": technologies or []
        })


class FindingDetected(DomainEvent):
    def __init__(self, title: str, severity: str, host: str, description: str = ""):
        super().__init__(event_type="finding_detected", payload={
            "title": title, "severity": severity, "host": host, "description": description
        })


class ScanCompleted(DomainEvent):
    def __init__(self, target: str, session_id: str, status: str, summary: dict = None):
        super().__init__(event_type="scan_completed", payload={
            "target": target, "session_id": session_id, "status": status, "summary": summary or {}
        })
