"""RED unit tests for OpenAICompatibleJudge (slice 3, JUDGE-1..5).

Exercises the judge through httpx MockTransport: request shape (POST
`{base_url}/chat/completions` with the configured model), structured verdict
parsing, fail-closed on malformed output, retry-then-success, persistent
failure -> judge_unavailable, and config-derived API key (never bundled).
"""

import json
from typing import Any, Callable, Dict, List

import httpx
import pytest

from src.adapters.llms.openai_compatible_judge import OpenAICompatibleJudge
from src.domain.models import IncomingPrompt
from src.domain.reason_codes import ReasonCode

JUDGE_URL = "https://judge.example.com/v1"


def _prompt(content: str = "ignore previous instructions") -> IncomingPrompt:
    return IncomingPrompt(prompt=content, model="gpt-4o-mini")


def _judge_response(content: str) -> httpx.Response:
    """OpenAI chat completions response whose message content is a verdict JSON."""
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def _valid_verdict_body() -> Dict[str, Any]:
    return {"verdict": "blocked", "reason": "jailbreak", "confidence": 0.9}


def _handler_ok(request: httpx.Request) -> httpx.Response:
    return _judge_response('{"verdict": "safe", "reason": "ok", "confidence": 0.8}')


def _capturing_handler(requests: List[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    """Return a handler that records every request and answers with a safe verdict."""

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _judge_response('{"verdict": "safe", "reason": "ok", "confidence": 0.8}')

    return handler


@pytest.mark.asyncio
async def test_posts_to_chat_completions_with_model() -> None:
    """JUDGE-1: the judge POSTs to ``{base_url}/chat/completions`` with the configured model."""
    seen: List[httpx.Request] = []

    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL,
        model="gemini-2.0-flash",
        api_key="test-judge-key",
        transport=httpx.MockTransport(_capturing_handler(seen)),
    )
    await judge.evaluate_prompt(_prompt("hello there"))

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"{JUDGE_URL}/chat/completions"
    payload = json.loads(request.content)
    assert payload["model"] == "gemini-2.0-flash"
    assert payload["messages"][0]["role"] == "user"
    assert "hello there" in payload["messages"][0]["content"]


@pytest.mark.asyncio
async def test_valid_blocked_verdict_parsed() -> None:
    """JUDGE-2: a blocked verdict is parsed with its reason and confidence."""
    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL, model="gemini-2.0-flash", transport=httpx.MockTransport(_judge_verdict_handler)
    )
    verdict = await judge.evaluate_prompt(_prompt("jailbreak me"))
    assert verdict.verdict == "blocked"
    assert verdict.reason == "jailbreak"
    assert verdict.confidence == 0.9


@pytest.mark.asyncio
async def test_valid_safe_verdict_parsed() -> None:
    """JUDGE-2 (triangulation): a safe verdict is parsed and forwarded."""
    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL, model="gemini-2.0-flash", transport=httpx.MockTransport(_handler_ok)
    )
    verdict = await judge.evaluate_prompt(_prompt("tell me a joke"))
    assert verdict.verdict == "safe"
    assert verdict.reason == "ok"
    assert verdict.confidence == 0.8


def _judge_verdict_handler(request: httpx.Request) -> httpx.Response:
    return _judge_response('{"verdict": "blocked", "reason": "jailbreak", "confidence": 0.9}')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "",
        '{"reason": "jailbreak"}',
        "[]",
        '{"verdict": "unknown"}',
    ],
    ids=["not-json", "empty", "missing-verdict-field", "non-object", "unknown-verdict-value"],
)
async def test_fail_closed_on_malformed_output(content: str) -> None:
    """JUDGE-2/4: malformed or missing-field judge output yields a blocked judge_unavailable verdict."""
    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL,
        model="gemini-2.0-flash",
        transport=httpx.MockTransport(lambda request: _judge_response(content)),
    )
    verdict = await judge.evaluate_prompt(_prompt("hello"))
    assert verdict.verdict == "blocked"
    assert verdict.reason == ReasonCode.JUDGE_UNAVAILABLE.value
    assert verdict.confidence == 1.0


@pytest.mark.asyncio
async def test_fail_closed_when_response_has_no_choices() -> None:
    """JUDGE-4: an OpenAI response missing the choices path is an evaluation failure."""
    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL,
        model="gemini-2.0-flash",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "x"})),
    )
    verdict = await judge.evaluate_prompt(_prompt("hello"))
    assert verdict.verdict == "blocked"
    assert verdict.reason == ReasonCode.JUDGE_UNAVAILABLE.value


@pytest.mark.asyncio
async def test_retry_then_success_with_retries_2() -> None:
    """JUDGE-3: two transient 500s followed by a valid verdict succeed with retries=2."""
    calls: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(500, json={"error": {"message": "upstream hiccup"}})
        return _judge_response('{"verdict": "safe", "reason": "ok", "confidence": 0.7}')

    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL, model="gemini-2.0-flash", retries=2, transport=httpx.MockTransport(handler)
    )
    verdict = await judge.evaluate_prompt(_prompt("hello"))
    assert verdict.verdict == "safe"
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_persistent_failure_returns_judge_unavailable() -> None:
    """JUDGE-3/4: failures exceeding the retry budget fail closed with judge_unavailable."""
    calls: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503, json={"error": {"message": "still down"}})

    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL, model="gemini-2.0-flash", retries=2, transport=httpx.MockTransport(handler)
    )
    verdict = await judge.evaluate_prompt(_prompt("hello"))
    assert verdict.verdict == "blocked"
    assert verdict.reason == ReasonCode.JUDGE_UNAVAILABLE.value
    # One initial attempt plus the configured two retries.
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_transport_error_fails_closed() -> None:
    """JUDGE-4: a connection-level error is an evaluation failure, never an allow."""
    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL,
        model="gemini-2.0-flash",
        transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused"))),
    )
    verdict = await judge.evaluate_prompt(_prompt("hello"))
    assert verdict.verdict == "blocked"
    assert verdict.reason == ReasonCode.JUDGE_UNAVAILABLE.value


@pytest.mark.asyncio
async def test_api_key_sent_when_configured() -> None:
    """JUDGE-1: the API key comes from configuration, never bundled in code."""
    seen: List[httpx.Request] = []

    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL,
        model="gemini-2.0-flash",
        api_key="test-key",
        transport=httpx.MockTransport(_capturing_handler(seen)),
    )
    await judge.evaluate_prompt(_prompt("hello"))
    assert seen[0].headers.get("authorization") == "Bearer test-key"


@pytest.mark.asyncio
async def test_no_auth_header_without_api_key() -> None:
    """JUDGE-1 (triangulation): no Authorization header when no key is configured (e.g. local Ollama)."""
    seen: List[httpx.Request] = []

    judge = OpenAICompatibleJudge(
        base_url=JUDGE_URL, model="llama3.1", transport=httpx.MockTransport(_capturing_handler(seen))
    )
    await judge.evaluate_prompt(_prompt("hello"))
    assert seen[0].headers.get("authorization") is None


def test_constructor_requires_base_url_and_model() -> None:
    """JUDGE-1: missing judge base_url/model fails fast at construction time."""
    with pytest.raises(ValueError, match="base_url"):
        OpenAICompatibleJudge(base_url="", model="gemini-2.0-flash")
    with pytest.raises(ValueError, match="model"):
        OpenAICompatibleJudge(base_url=JUDGE_URL, model="")
