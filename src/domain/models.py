from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

@dataclass(frozen=True)
class Service:
    """Open port and detected service information."""
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None

@dataclass(frozen=True)
class Asset:
    """A host or domain identified during reconnaissance."""
    domain: str
    type: str  # e.g., 'domain', 'subdomain', 'ip'
    ip: Optional[str] = None
    is_live: bool = False
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    services: List[Service] = field(default_factory=list)

@dataclass(frozen=True)
class Evidence:
    """Proof of a finding or hypothesis validation."""
    content: str
    source: str
    content_hash: str
    signature: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Finding:
    """A security issue or interesting discovery on an asset."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    asset_id: str  # References an Asset (domain or ip)
    evidence_ids: List[str] = field(default_factory=list)
    vulnerability_type: Optional[str] = None
    path: Optional[str] = None
    param: Optional[str] = None

@dataclass(frozen=True)
class Scan:
    """A reconnaissance execution session."""
    id: str
    session_id: str
    target: str
    status: str = "pending"  # pending, running, completed, failed
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    stats: Dict[str, int] = field(default_factory=lambda: {
        "subdomains": 0,
        "hosts_alive": 0,
        "ports_found": 0,
        "findings": 0
    })
