"""
FastAPI proxy app: OpenAI-compatible guardrail endpoint (guardrail-pivot slice 3).

Request flow: pydantic parse (422) → KeyStore.verify_key (401) → scope check
(403 insufficient_scope) → per-key rate limit (429 + Retry-After) →
GuardrailDecisionService (403 on block) → upstream passthrough (LLM-PROXY-4)
or buffer-then-judge SSE relay (LLM-PROXY-7) → JSONL audit append (service
side). `_MASTER_KEYS` is gone: auth is KeyStore-only (LLM-PROXY-2). The
upstream key comes from env (PROMPTWALL_UPSTREAM_API_KEY) — never the client
key. Missing judge base_url/model fails loudly at startup (JUDGE-1); the
proxy is fail-closed by default (AD-8).
"""

from __future__ import annotations

import math
import os
import time
from collections import defaultdict
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from src.adapters.llms.openai_compatible_judge import OpenAICompatibleJudge
from src.application.guardrail_service import GuardrailDecisionService
from src.auth.key_store import KeyStore
from src.auth.key_store import key_store as default_key_store
from src.core.config import config
from src.domain.models import IncomingPrompt
from src.domain.reason_codes import ReasonCode


class ChatMessage(BaseModel):
    """One message in an OpenAI chat completions request."""

    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request body (LLM-PROXY-1)."""

    model: str
    messages: list[ChatMessage]
    stream: bool = False
    temperature: Optional[float] = None


class _PerKeyRateLimiter:
    """Fixed-window per-key rate limiter.

    ponytail: in-memory per-process buckets; a shared store is needed once the
    proxy runs multi-process.
    """

    def __init__(self) -> None:
        self._hits: Dict[str, list[float]] = defaultdict(list)

    def check(self, key_name: str, limit_per_min: int) -> Optional[int]:
        """Register one hit; return Retry-After seconds if the limit is exceeded."""
        now = time.monotonic()
        hits = [t for t in self._hits[key_name] if t > now - 60.0]
        if limit_per_min <= 0:
            return 60
        if len(hits) >= limit_per_min:
            return max(1, math.ceil(60.0 - (now - hits[0])))
        hits.append(now)
        self._hits[key_name] = hits
        return None


def _error_response(status: int, code: str, reason: str, message: str, **extra: Any) -> JSONResponse:
    """Build a machine-readable error body: ``{"error": {...}}`` (design 403 shape)."""
    payload: Dict[str, Any] = {"code": code, "reason": reason, "message": message}
    payload.update(extra)
    return JSONResponse(status_code=status, content={"error": payload})


def _bearer_token(request: Request) -> Optional[str]:
    """Extract the Bearer token from the Authorization header, if present."""
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _judge_from_config() -> OpenAICompatibleJudge:
    """Build the judge from guardrail.judge config.

    Missing base_url/model raises loudly so the proxy cannot start without
    judge configuration (JUDGE-1, fail fast).
    """
    return OpenAICompatibleJudge(
        base_url=config.guardrail_judge_base_url,
        model=config.guardrail_judge_model,
        api_key=os.environ.get(config.guardrail_judge_api_key_env),
        timeout_seconds=config.guardrail_judge_timeout_seconds,
        retries=config.guardrail_judge_retries,
    )


def _upstream_client_from_config() -> httpx.AsyncClient:
    """Upstream client: base_url from config, API key from env — never bundled (LLM-PROXY-4)."""
    key = os.environ.get(config.guardrail_upstream_api_key_env)
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return httpx.AsyncClient(base_url=config.guardrail_upstream_base_url, headers=headers, timeout=60.0)


async def _relay_upstream(client: httpx.AsyncClient, body: ChatCompletionRequest) -> Response:
    """Forward an allowed request upstream (LLM-PROXY-4) or relay its SSE stream (LLM-PROXY-7).

    The upstream Authorization header is set on the client (config/env key) —
    the client's key is never forwarded. Any 5xx or transport error yields a
    generic 502 with no upstream internals.
    """
    url = f"{str(client.base_url).rstrip('/')}/chat/completions"
    payload = body.model_dump(exclude_none=True)
    try:
        if body.stream:
            upstream_response = await client.send(client.build_request("POST", url, json=payload), stream=True)
            if upstream_response.status_code >= 500:
                await upstream_response.aclose()
                return _error_response(
                    502, ReasonCode.UPSTREAM_FAILURE.value, "upstream error", "Upstream request failed"
                )
            return StreamingResponse(
                upstream_response.aiter_bytes(),
                media_type="text/event-stream",
                status_code=upstream_response.status_code,
            )
        upstream_response = await client.post(url, json=payload)
        if upstream_response.status_code >= 500:
            return _error_response(
                502, ReasonCode.UPSTREAM_FAILURE.value, "upstream error", "Upstream request failed"
            )
        return JSONResponse(status_code=upstream_response.status_code, content=upstream_response.json())
    except httpx.HTTPError:
        return _error_response(502, ReasonCode.UPSTREAM_FAILURE.value, "upstream unreachable", "Upstream request failed")


def create_app(
    *,
    key_store: Optional[KeyStore] = None,
    decision_service: Optional[GuardrailDecisionService] = None,
    upstream_client: Optional[httpx.AsyncClient] = None,
) -> FastAPI:
    """Build the proxy app: auth, per-key rate limit, decision service and upstream relay."""
    ks = key_store or default_key_store
    service = decision_service or GuardrailDecisionService(judge=_judge_from_config(), audit_path=config.guardrail_audit_path)
    upstream = upstream_client or _upstream_client_from_config()
    limiter = _PerKeyRateLimiter()

    app = FastAPI(title="PromptWall Guardrail Proxy", version="0.10.0")

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(
            422,
            ReasonCode.VALIDATION_ERROR.value,
            "malformed request body",
            "Request body failed validation",
            details=exc.errors(),
        )

    @app.get("/")
    def root() -> Dict[str, Any]:
        return {"name": "PromptWall", "version": app.version}

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request, body: ChatCompletionRequest) -> Response:
        token = _bearer_token(request)
        key_data = ks.verify_key(token) if token else None
        if key_data is None:
            return _error_response(
                401, ReasonCode.UNAUTHENTICATED.value, "missing, invalid or disabled key", "Unauthorized"
            )
        if "chat" not in key_data.get("scopes", []):
            return _error_response(403, ReasonCode.INSUFFICIENT_SCOPE.value, "missing chat scope", "Insufficient scope")
        retry_after = limiter.check(key_data["name"], int(key_data.get("rate_limit_per_min", 60)))
        if retry_after is not None:
            response = _error_response(
                429, ReasonCode.RATE_LIMIT_EXCEEDED.value, "per-minute limit exceeded", "Rate limit exceeded"
            )
            response.headers["Retry-After"] = str(retry_after)
            return response
        prompt = IncomingPrompt(
            prompt="\n".join(message.content for message in body.messages),
            model=body.model,
            stream=body.stream,
        )
        decision = await service.decide(prompt, key_data)
        if decision.outcome == "blocked":
            return _error_response(
                403,
                decision.reason_code or ReasonCode.JUDGE_BLOCK.value,
                decision.reason,
                "Request blocked by guardrail",
                decision_id=decision.decision_id,
            )
        return await _relay_upstream(upstream, body)

    return app


app = create_app()


def start_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the proxy app with uvicorn."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


__all__ = ["app", "start_api", "create_app"]
