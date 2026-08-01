"""OpenAI-compatible judge LLM adapter (guardrail-pivot slice 3, JUDGE-1..5).

Posts the guardrail instruction plus the prompt to
``{base_url}/chat/completions`` — Gemini/OpenAI/Ollama interchangeable via
the configured base_url (AD-2) — parses the structured verdict JSON from the
first choice's content and fails closed (blocked / judge_unavailable) on any
error, timeout or malformed output (JUDGE-4, AD-8).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from src.application.guardrail_service import JUDGE_PROMPT_TEMPLATE, parse_verdict
from src.domain.models import IncomingPrompt, Verdict
from src.domain.reason_codes import ReasonCode

logger = logging.getLogger(__name__)


class OpenAICompatibleJudge:
    """Judge LLM over the OpenAI chat completions protocol (JUDGE-1..5).

    The API key is supplied from config/env at construction time — never
    bundled in code. A missing ``base_url`` or ``model`` fails fast so the
    proxy cannot start without judge configuration (JUDGE-1).
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: Optional[str] = None,
        timeout_seconds: float = 10.0,
        retries: int = 2,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not base_url:
            raise ValueError("guardrail.judge.base_url is required (JUDGE-1)")
        if not model:
            raise ValueError("guardrail.judge.model is required (JUDGE-1)")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.retries = retries
        # transport injectable for httpx.MockTransport unit tests.
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout_seconds)

    async def evaluate_prompt(self, prompt: IncomingPrompt) -> Verdict:
        """Evaluate one prompt; fail closed (judge_unavailable) on any error."""
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: Dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "user", "content": JUDGE_PROMPT_TEMPLATE + prompt.prompt}],
        }
        for _ in range(self.retries + 1):
            try:
                response = await self._client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return parse_verdict(content)
            except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                logger.warning("Judge LLM attempt failed (%s): %s", type(exc).__name__, exc)
        return Verdict(verdict="blocked", reason=ReasonCode.JUDGE_UNAVAILABLE.value, confidence=1.0)


__all__ = ["OpenAICompatibleJudge"]
