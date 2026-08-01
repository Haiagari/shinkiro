"""Unit tests for guardrail domain: reason codes, models, events, contracts (T2.2)."""

from dataclasses import FrozenInstanceError

import pytest

from src.domain.events import DecisionRecorded, PromptForwarded
from src.domain.models import IncomingPrompt, PolicyDecision, UpstreamResponse, Verdict
from src.domain.reason_codes import ReasonCode


def test_reason_code_has_twelve_stable_codes() -> None:
    """The ReasonCode enum carries exactly the 12 design codes."""
    assert len(ReasonCode) == 12
    assert {rc.value for rc in ReasonCode} == {
        "policy_block",
        "judge_block",
        "judge_unavailable",
        "injection",
        "jailbreak",
        "pii_exfiltration",
        "insufficient_scope",
        "unauthenticated",
        "rate_limit_exceeded",
        "validation_error",
        "upstream_failure",
        "not_found",
    }


def test_reason_code_key_values() -> None:
    """Key codes used by the proxy responses keep their stable values."""
    assert ReasonCode.POLICY_BLOCK.value == "policy_block"
    assert ReasonCode.JUDGE_UNAVAILABLE.value == "judge_unavailable"
    assert ReasonCode.RATE_LIMIT_EXCEEDED.value == "rate_limit_exceeded"
    assert ReasonCode.UPSTREAM_FAILURE.value == "upstream_failure"


def test_incoming_prompt_frozen_with_defaults() -> None:
    """IncomingPrompt is a frozen dataclass with auto id/timestamp."""
    prompt = IncomingPrompt(prompt="hello", model="gpt-4o-mini", stream=True)
    assert prompt.prompt == "hello"
    assert prompt.model == "gpt-4o-mini"
    assert prompt.stream is True
    assert prompt.id
    with pytest.raises(FrozenInstanceError):
        prompt.prompt = "mutated"


def test_upstream_response_frozen() -> None:
    """UpstreamResponse is a frozen dataclass carrying the upstream body."""
    response = UpstreamResponse(id="u1", decision_id="dec_1", status_code=200, body={"ok": True})
    assert response.status_code == 200
    assert response.body == {"ok": True}
    with pytest.raises(FrozenInstanceError):
        response.body = {}


def test_verdict_and_policy_decision_values() -> None:
    """Verdict and PolicyDecision expose their evaluation outcome."""
    verdict = Verdict(verdict="blocked", reason="jailbreak", confidence=0.9)
    assert verdict.verdict == "blocked"
    assert verdict.reason == "jailbreak"
    decision = PolicyDecision(action="allow")
    assert decision.action == "allow"
    assert decision.reason_code is None
    assert decision.rule_id is None


def test_guardrail_events_instantiable() -> None:
    """PromptForwarded and DecisionRecorded events carry their payloads."""
    prompt = IncomingPrompt(prompt="hi", model="m")
    forwarded = PromptForwarded(prompt=prompt)
    assert forwarded.type == "prompt_forwarded"
    assert forwarded.prompt == prompt
    recorded = DecisionRecorded(decision_id="dec_1", outcome="forwarded")
    assert recorded.type == "decision_recorded"
    assert recorded.reason_code is None


@pytest.mark.asyncio
async def test_ijudge_llm_contract_returns_verdict() -> None:
    """IJudgeLLM.evaluate_prompt is the only abstract method and yields a Verdict."""
    from src.core.contracts import IJudgeLLM

    class StubJudge(IJudgeLLM):
        async def evaluate_prompt(self, prompt: IncomingPrompt) -> Verdict:
            return Verdict(verdict="safe", reason="ok", confidence=1.0)

    judge = StubJudge()
    result = await judge.evaluate_prompt(IncomingPrompt(prompt="hi", model="m"))
    assert isinstance(result, Verdict)
    assert result.verdict == "safe"
