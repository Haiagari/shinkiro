from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4
from src.domain.models import AttackPayload, TargetResponse, EvaluationResult, AttackPath

@dataclass(frozen=True, kw_only=True)
class DomainEvent:
    """Base class for all domain events."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    type: str = "domain_event"

@dataclass(frozen=True, kw_only=True)
class AttackAttempted(DomainEvent):
    """Event emitted when an attack payload is generated."""
    payload: AttackPayload
    type: str = "attack_attempted"

@dataclass(frozen=True, kw_only=True)
class TargetResponded(DomainEvent):
    """Event emitted when the target responds to a payload."""
    response: TargetResponse
    type: str = "target_responded"

@dataclass(frozen=True, kw_only=True)
class GuardrailBypassed(DomainEvent):
    """Event emitted when the judge determines the guardrail was bypassed."""
    result: EvaluationResult
    path: AttackPath
    type: str = "guardrail_bypassed"

@dataclass(frozen=True, kw_only=True)
class AttackFailed(DomainEvent):
    """Event emitted when the judge determines the attack failed to bypass the guardrail."""
    result: EvaluationResult
    type: str = "attack_failed"
