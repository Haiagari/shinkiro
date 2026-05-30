from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4
from src.domain.models import Asset, Finding

@dataclass(frozen=True, kw_only=True)
class DomainEvent:
    """Base class for all domain events."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    type: str = "domain_event"

@dataclass(frozen=True, kw_only=True)
class AssetDiscovered(DomainEvent):
    """Event emitted when a new asset is identified."""
    asset: Asset
    type: str = "asset_discovered"

@dataclass(frozen=True, kw_only=True)
class FindingDetected(DomainEvent):
    """Event emitted when a new security finding is detected."""
    finding: Finding
    type: str = "finding_detected"
