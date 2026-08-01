"""Integration tests for the guardrail proxy skeleton (slice 2, LLM-PROXY-1..3).

Exercises POST /v1/chat/completions through a real FastAPI app wired with a
temp KeyStore, a per-key rate limiter and a MockProvider-backed decision
service: 422 malformed body, 401 missing/invalid/disabled key,
403 insufficient_scope, 429 + Retry-After, and a within-limit pass.
"""

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from httpx import ASGITransport, AsyncClient

from src.adapters.llms.provider_base import MockProvider
from src.application.guardrail_service import GuardrailDecisionService
from src.auth.key_store import KeyStore
from src.core.api import create_app


def _chat_body(content: str = "Hello there") -> Dict[str, Any]:
    """Build a minimal OpenAI chat completions body."""
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": content}]}


def _auth(key: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _disable_key(store_path: Path, name: str) -> None:
    """Flip a key entry to enabled=False directly in the JSON store."""
    data = json.loads(store_path.read_text())
    for entry in data["keys"]:
        if entry["name"] == name:
            entry["enabled"] = False
    store_path.write_text(json.dumps(data, indent=2))


@pytest.fixture()
def proxy_env(tmp_path: Path) -> Dict[str, Any]:
    """Build an app with a temp KeyStore, audit path and MockProvider service."""
    store = KeyStore(storage_path=str(tmp_path / "api_keys.json"))
    _, key_chat = store.create_key("app-chat", scopes=["chat"], rate_limit=60, prefix="pw_test_")
    _, key_audit = store.create_key("app-audit", scopes=["audit"], rate_limit=60, prefix="pw_test_")
    _, key_limited = store.create_key("app-limited", scopes=["chat"], rate_limit=2, prefix="pw_test_")
    _, key_disabled = store.create_key("app-disabled", scopes=["chat"], rate_limit=60, prefix="pw_test_")
    _disable_key(store.storage_path, "app-disabled")
    audit_path = tmp_path / "audit.jsonl"
    service = GuardrailDecisionService(judge=MockProvider(), audit_path=audit_path)
    app = create_app(key_store=store, decision_service=service)
    return {
        "app": app,
        "audit_path": audit_path,
        "key_chat": key_chat,
        "key_audit": key_audit,
        "key_limited": key_limited,
        "key_disabled": key_disabled,
        "store_path": store.storage_path,
    }


@pytest.mark.asyncio
async def test_malformed_body_returns_422(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-1: invalid JSON body -> 422 validation_error, no evaluation."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=b'{"model": ',
            headers={"content-type": "application/json", **_auth(proxy_env["key_chat"])},
        )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_missing_key_returns_401(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-2: no Authorization header -> 401 unauthenticated."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post("/v1/chat/completions", json=_chat_body())
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthenticated"


@pytest.mark.asyncio
async def test_invalid_key_returns_401(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-2: unknown key -> 401 unauthenticated."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth("pw_test_bogus_00000000000000000000000000000000")
        )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthenticated"


@pytest.mark.asyncio
async def test_disabled_key_returns_401(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-2: disabled key -> 401 unauthenticated."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth(proxy_env["key_disabled"])
        )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthenticated"


@pytest.mark.asyncio
async def test_insufficient_scope_returns_403(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-2: valid key without chat scope -> 403 insufficient_scope."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth(proxy_env["key_audit"])
        )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "insufficient_scope"


@pytest.mark.asyncio
async def test_rate_limit_returns_429_with_retry_after(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-3: exceeding the per-key limit -> 429 + Retry-After header."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        first = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth(proxy_env["key_limited"])
        )
        second = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth(proxy_env["key_limited"])
        )
        third = await client.post(
            "/v1/chat/completions", json=_chat_body(), headers=_auth(proxy_env["key_limited"])
        )
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["error"]["code"] == "rate_limit_exceeded"
    retry_after = third.headers.get("Retry-After")
    assert retry_after is not None
    assert int(retry_after) >= 1
    # The rate-limited request never reached the decision service: no audit entry for it.
    audit_lines = [line for line in proxy_env["audit_path"].read_text().splitlines() if line.strip()]
    assert len(audit_lines) == 2


@pytest.mark.asyncio
async def test_within_limit_pass(proxy_env: Dict[str, Any]) -> None:
    """LLM-PROXY-1/3: valid key under the limit -> 200 OpenAI-shaped completion + audit entry."""
    async with AsyncClient(transport=ASGITransport(app=proxy_env["app"]), base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions", json=_chat_body(content="Tell me a joke"), headers=_auth(proxy_env["key_chat"])
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["role"] == "assistant"
    assert body["choices"][0]["message"]["content"]
    audit_lines = [line for line in proxy_env["audit_path"].read_text().splitlines() if line.strip()]
    assert len(audit_lines) == 1
    entry = json.loads(audit_lines[0])
    assert entry["outcome"] == "forwarded"
    assert entry["key_name"] == "app-chat"
    assert entry["prompt_hash"].startswith("sha256:")
    assert entry["decision_id"].startswith("dec_")
