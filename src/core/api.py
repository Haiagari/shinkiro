"""
FastAPI proxy app: OpenAI-compatible guardrail endpoint (guardrail-pivot slice 2).

Request flow: pydantic parse (422) → KeyStore.verify_key (401) → scope check
(403 insufficient_scope) → per-key rate limit (429 + Retry-After) →
GuardrailDecisionService (403 on block, 200 OpenAI-shaped completion
otherwise) → JSONL audit append (service side). `_MASTER_KEYS` is gone:
auth is KeyStore-only (LLM-PROXY-2). Upstream passthrough lands in slice 3.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.adapters.llms.provider_base import MockProvider
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


def _stub_completion(model: str) -> JSONResponse:
    """Return a minimal OpenAI-shaped completion (real passthrough lands in slice 3)."""
    return JSONResponse(
        status_code=200,
        content={
            "id": f"chatcmpl-{uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Mock upstream response (passthrough in slice 3)."},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        },
    )


def create_app(
    *,
    key_store: Optional[KeyStore] = None,
    decision_service: Optional[GuardrailDecisionService] = None,
) -> FastAPI:
    """Build the proxy app, wiring auth, per-key rate limiting and the decision service."""
    ks = key_store or default_key_store
    service = decision_service or GuardrailDecisionService(judge=MockProvider(), audit_path=config.guardrail_audit_path)
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
    async def chat_completions(request: Request, body: ChatCompletionRequest) -> JSONResponse:
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
        return _stub_completion(body.model)

    return app


app = create_app()


def start_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the proxy app with uvicorn."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


__all__ = ["app", "start_api", "create_app"]
