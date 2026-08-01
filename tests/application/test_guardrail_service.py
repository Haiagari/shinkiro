"""Unit tests for GuardrailDecisionService: policy → judge → decision + audit (T2.4).

The service must record a decision and append a JSONL audit entry for every
outcome: forwarded, judge block, and fail-closed judge unavailable.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from src.adapters.llms.provider_base import AIProvider, MockProvider
from src.application.guardrail_service import GuardrailDecisionService, parse_verdict
from src.domain.models import IncomingPrompt, Verdict
from src.domain.reason_codes import ReasonCode


class BlockingProvider(AIProvider):
    """Provider whose output carries a blocked verdict."""

    def generate_content(self, prompt: str) -> Optional[str]:
        return '{"verdict": "blocked", "reason": "jailbreak", "confidence": 0.95}'


class SilentProvider(AIProvider):
    """Provider that never returns a verdict (judge unavailable)."""

    def generate_content(self, prompt: str) -> Optional[str]:
        return None


class AsyncSafeJudge:
    """Judge speaking the async IJudgeLLM contract (slice 3: OpenAICompatibleJudge)."""

    async def evaluate_prompt(self, prompt: IncomingPrompt) -> Verdict:
        return Verdict(verdict="safe", reason="ok", confidence=0.9)


class AsyncBlockingJudge:
    """Async judge that returns a blocked verdict."""

    async def evaluate_prompt(self, prompt: IncomingPrompt) -> Verdict:
        return Verdict(verdict="blocked", reason="jailbreak", confidence=0.95)


def _prompt(content: str = "Hello") -> IncomingPrompt:
    return IncomingPrompt(prompt=content, model="gpt-4o-mini")


def _key() -> Dict[str, Any]:
    return {"name": "app-a", "scopes": ["chat"], "rate_limit_per_min": 60, "enabled": True}


def _read_audit(path: Path) -> list[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_parse_verdict_safe() -> None:
    verdict = parse_verdict('{"verdict": "safe", "reason": "ok", "confidence": 0.8}')
    assert verdict.verdict == "safe"
    assert verdict.confidence == 0.8


def test_parse_verdict_blocked() -> None:
    verdict = parse_verdict('{"verdict": "blocked", "reason": "jailbreak", "confidence": 0.9}')
    assert verdict.verdict == "blocked"
    assert verdict.reason == "jailbreak"


def test_parse_verdict_fail_closed_on_missing_or_malformed() -> None:
    """No output or unparseable output must yield a blocked verdict (fail-closed)."""
    assert parse_verdict(None).verdict == "blocked"
    assert parse_verdict(None).reason == ReasonCode.JUDGE_UNAVAILABLE.value
    assert parse_verdict("not json").verdict == "blocked"
    assert parse_verdict("").verdict == "blocked"


def test_parse_verdict_fail_closed_on_non_verdict_json() -> None:
    """JSON without an explicit safe verdict must be blocked (AD-8 fail-closed)."""
    verdict = parse_verdict('{"analysis": "mock-analysis", "business_impact": "LOW"}')
    assert verdict.verdict == "blocked"
    assert verdict.reason == ReasonCode.JUDGE_UNAVAILABLE.value
    assert parse_verdict("[]").verdict == "blocked"
    assert parse_verdict('"str"').verdict == "blocked"
    assert parse_verdict('{"verdict": "unknown"}').verdict == "blocked"
    assert parse_verdict('{"verdict": "unknown"}').reason == ReasonCode.JUDGE_UNAVAILABLE.value


@pytest.mark.asyncio
async def test_decide_forwards_safe_prompt_and_writes_audit(tmp_path: Path) -> None:
    service = GuardrailDecisionService(judge=MockProvider(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("Tell me a joke"), _key())
    assert decision.outcome == "forwarded"
    assert decision.reason_code is None
    assert decision.key_name == "app-a"
    assert decision.prompt_hash.startswith("sha256:")
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    assert entries[0]["outcome"] == "forwarded"
    assert entries[0]["decision_id"] == decision.decision_id
    assert entries[0]["key_name"] == "app-a"
    # Privacy: audit entries carry prompt_hash, never the prompt text (AUDIT-2).
    assert "Tell me a joke" not in json.dumps(entries[0])


@pytest.mark.asyncio
async def test_decide_blocks_and_writes_audit(tmp_path: Path) -> None:
    service = GuardrailDecisionService(judge=BlockingProvider(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("jailbreak attempt"), _key())
    assert decision.outcome == "blocked"
    assert decision.reason_code == ReasonCode.JUDGE_BLOCK.value
    assert decision.reason == "jailbreak"
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    assert entries[0]["outcome"] == "blocked"
    assert entries[0]["reason_code"] == ReasonCode.JUDGE_BLOCK.value


@pytest.mark.asyncio
async def test_decide_fail_closed_on_judge_unavailable(tmp_path: Path) -> None:
    service = GuardrailDecisionService(judge=SilentProvider(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("hello"), _key())
    assert decision.outcome == "blocked"
    assert decision.reason_code == ReasonCode.JUDGE_UNAVAILABLE.value
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    assert entries[0]["reason_code"] == ReasonCode.JUDGE_UNAVAILABLE.value


@pytest.mark.asyncio
async def test_audit_entry_records_judge_confidence(tmp_path: Path) -> None:
    """JUDGE-5: the JSONL audit entry must carry the judge's confidence."""
    service = GuardrailDecisionService(judge=AsyncSafeJudge(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("hello"), _key())
    assert decision.confidence == 0.9
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert entries[0]["confidence"] == 0.9


@pytest.mark.asyncio
async def test_decide_uses_async_judge_contract(tmp_path: Path) -> None:
    """Slice 3: a judge implementing the async evaluate_prompt contract is awaited."""
    service = GuardrailDecisionService(judge=AsyncSafeJudge(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("hello"), _key())
    assert decision.outcome == "forwarded"
    assert decision.reason_code is None
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert entries[0]["outcome"] == "forwarded"


@pytest.mark.asyncio
async def test_decide_async_judge_blocked(tmp_path: Path) -> None:
    """Slice 3: an async blocked verdict maps to judge_block and is audited."""
    service = GuardrailDecisionService(judge=AsyncBlockingJudge(), audit_path=tmp_path / "audit.jsonl")
    decision = await service.decide(_prompt("jailbreak attempt"), _key())
    assert decision.outcome == "blocked"
    assert decision.reason_code == ReasonCode.JUDGE_BLOCK.value
    assert decision.reason == "jailbreak"
    entries = _read_audit(tmp_path / "audit.jsonl")
    assert entries[0]["reason_code"] == ReasonCode.JUDGE_BLOCK.value
