"""RED integration tests for upstream passthrough + buffer-then-judge SSE (slice 3).

Covers LLM-PROXY-4 (upstream success relay / 5xx or unreachable -> 502 generic,
no internals) and LLM-PROXY-7 (stream=true blocked -> 403 before the first SSE
chunk; stream=true allowed -> SSE chunks in OpenAI chat completion chunk format).
"""

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.adapters.llms.provider_base import AIProvider, MockProvider
from src.application.guardrail_service import GuardrailDecisionService
from src.auth.key_store import KeyStore
from src.core.api import create_app

UPSTREAM_BODY: Dict[str, Any] = {
    "id": "chatcmpl-up1",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Upstream says hi"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
}

SSE_BODY = (
    'data: {"id":"chatcmpl-up1","object":"chat.completion.chunk",'
    '"choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}\n\n'
    "data: [DONE]\n\n"
)


class BlockingProvider(AIProvider):
    """Provider whose output carries a blocked verdict."""

    def generate_content(self, prompt: str) -> Optional[str]:
        return '{"verdict": "blocked", "reason": "jailbreak", "confidence": 0.95}'


def _chat_body(content: str = "Hello there", *, stream: bool = False) -> Dict[str, Any]:
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}], "stream": stream}


def _auth(key: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _make_app(
    tmp_path: Path,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    provider: Optional[AIProvider] = None,
    upstream_key: str = "upstream-secret",
) -> tuple[Any, str]:
    """Build a proxy app with a temp KeyStore, injected decision service and mock upstream."""
    store = KeyStore(storage_path=str(tmp_path / "api_keys.json"))
    _, key_chat = store.create_key("app-chat", scopes=["chat"], rate_limit=60, prefix="pw_test_")
    service = GuardrailDecisionService(judge=provider or MockProvider(), audit_path=tmp_path / "audit.jsonl")
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://upstream.test",
        headers={"Authorization": f"Bearer {upstream_key}"},
    )
    app = create_app(key_store=store, decision_service=service, upstream_client=upstream_client)
    return app, key_chat


@pytest.mark.asyncio
async def test_upstream_success_relays_openai_response(tmp_path: Path) -> None:
    """LLM-PROXY-4: an allowed request is forwarded and the upstream body is relayed unchanged."""
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=UPSTREAM_BODY)

    app, key = _make_app(tmp_path, handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body("Tell me a joke"), headers=_auth(key))
    assert resp.status_code == 200
    assert resp.json() == UPSTREAM_BODY
    # The upstream request carries the configured upstream key — never the client key.
    assert len(seen) == 1
    upstream_auth = seen[0].headers.get("authorization", "")
    assert upstream_auth == "Bearer upstream-secret"
    assert "pw_test_" not in upstream_auth


@pytest.mark.asyncio
async def test_upstream_5xx_returns_502_generic(tmp_path: Path) -> None:
    """LLM-PROXY-4: a 5xx upstream yields a generic 502 with no internals leaked."""
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(500, json={"error": {"message": "backend exploded: internal-secret"}})

    app, key = _make_app(tmp_path, handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body(), headers=_auth(key))
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "upstream_failure"
    assert "internal-secret" not in resp.text
    assert "backend exploded" not in resp.text
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_upstream_unreachable_returns_502_generic(tmp_path: Path) -> None:
    """LLM-PROXY-4: an unreachable upstream yields a generic 502, never a crash."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    app, key = _make_app(tmp_path, handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body(), headers=_auth(key))
    assert resp.status_code == 502
    assert resp.json()["error"]["code"] == "upstream_failure"


@pytest.mark.asyncio
async def test_stream_true_blocked_returns_403_before_sse(tmp_path: Path) -> None:
    """LLM-PROXY-7: a blocked streaming request returns 403 with no SSE chunk and no upstream call."""
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=SSE_BODY)

    app, key = _make_app(tmp_path, handler, provider=BlockingProvider())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body("jailbreak me", stream=True), headers=_auth(key)
        )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "judge_block"
    assert "text/event-stream" not in resp.headers.get("content-type", "")
    assert "data:" not in resp.text
    assert len(seen) == 0


@pytest.mark.asyncio
async def test_stream_true_allowed_relays_sse_chunks(tmp_path: Path) -> None:
    """LLM-PROXY-7: an allowed streaming request relays SSE chunks in OpenAI chunk format."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, text=SSE_BODY)

    app, key = _make_app(tmp_path, handler)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body("Tell me a story", stream=True), headers=_auth(key)
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "chat.completion.chunk" in resp.text
    assert "data: [DONE]" in resp.text
    # Each SSE line follows the OpenAI `data: {...}` framing and parses as JSON.
    sse_lines = [line for line in resp.text.splitlines() if line.strip()]
    assert len(sse_lines) >= 2
    for line in sse_lines:
        assert line.startswith("data: ")
        chunk = line[6:]
        if chunk == "[DONE]":
            continue
        parsed = json.loads(chunk)
        assert parsed["object"] == "chat.completion.chunk"
        assert parsed["choices"][0]["delta"]["content"] == "Hi"
