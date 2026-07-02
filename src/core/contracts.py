"""
Runtime contract constants for OzyRecon.

These values define the stable shape that the local engine exposes.
"""

from abc import ABC, abstractmethod
from typing import Dict, Iterable, Tuple, Any, List

from src.domain.models import AttackPayload, TargetResponse, EvaluationResult

CONTRACT_VERSION = "ozy.runtime.v1"

MODE_ENVELOPE_FIELDS: Tuple[str, ...] = (
    "status",
    "session_id",
    "target",
    "mode",
    "contract_version",
    "result",
    "observability",
)

SESSION_TRACE_FIELDS: Tuple[str, ...] = (
    "session_id",
    "target",
    "mode",
    "scan",
    "session",
    "workflow_steps",
    "evidence",
    "decisions",
    "summary",
)

SCAN_RESULT_FIELDS: Tuple[str, ...] = (
    "type",
    "source",
    "version",
    "contract_version",
    "session_id",
    "target",
    "mode",
    "timestamp",
    "started_at",
    "ended_at",
    "duration_seconds",
    "assets",
    "services",
    "findings",
    "diff",
    "stats",
    "config",
    "errors",
)


def missing_fields(payload: Dict[str, object], required: Iterable[str]) -> list[str]:
    """Return required fields that are missing from a payload."""
    return [field for field in required if field not in payload]


def validate_required_fields(payload: Dict[str, object], required: Iterable[str]) -> None:
    """Raise if a payload is missing required contract fields."""
    missing = missing_fields(payload, required)
    if missing:
        raise ValueError(f"Missing contract fields: {', '.join(missing)}")


class IAttackerLLM(ABC):
    """Interface for the Attacker LLM that generates malicious payloads."""

    @abstractmethod
    async def generate_payload(self, context: dict, previous_responses: list) -> AttackPayload:
        pass


class ITargetAPI(ABC):
    """Interface for the Target API that receives payloads."""

    @abstractmethod
    async def send_prompt(self, payload: AttackPayload) -> TargetResponse:
        pass


class IJudgeLLM(ABC):
    """Interface for the Judge LLM that evaluates responses."""

    @abstractmethod
    async def evaluate_response(self, payload: AttackPayload, response: TargetResponse, criteria: dict) -> EvaluationResult:
        pass

    @abstractmethod
    async def evaluate_prompt(self, payload: AttackPayload) -> EvaluationResult:
        pass

