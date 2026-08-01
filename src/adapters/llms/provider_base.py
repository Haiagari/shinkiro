"""
AI provider abstraction for PromptWall (guardrail-pivot).

Extracted from the v9 `src/intelligence/ai_analyzer.py` module. Serves as
the judge-LLM base: deterministic MockProvider plus OpenAI-compatible
backends (Gemini, OpenAI, Ollama) that share the `AIProvider` contract.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class AIProvider(ABC):
    @abstractmethod
    def generate_content(self, prompt: str) -> Optional[str]:
        pass


class MockProvider(AIProvider):
    """Deterministic provider used when no real backend is available."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def generate_content(self, prompt: str) -> Optional[str]:
        # ponytail: deterministic dev-mode judge; always explicit verdict so the
        # fail-closed parser (guardrail_service.parse_verdict) allows mock traffic.
        return '{"verdict": "safe", "reason": "mock analysis", "confidence": 0.5}'


class GeminiProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        try:
            import google.generativeai as genai

            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel("gemini-1.5-flash")
        except Exception as e:
            logger.warning("Failed to initialize Gemini: %s", e)
            self.model = None

    def generate_content(self, prompt: str) -> Optional[str]:
        if not self.model:
            return None
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception:
            return None


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key
        try:
            from openai import OpenAI

            self.client = OpenAI(api_key=api_key)
        except Exception as e:
            logger.warning("Failed to initialize OpenAI provider: %s", e)
            self.client = None

    def generate_content(self, prompt: str) -> Optional[str]:
        if not self.client:
            return None
        try:
            response = self.client.responses.create(
                model="gpt-4.1-mini",
                input=prompt,
            )
            return getattr(response, "output_text", None)
        except Exception as e:
            logger.warning("OpenAI generation failed: %s", e)
            return None


class OllamaProvider(AIProvider):
    def __init__(self, api_key: str | None = None, model: str = "llama3.1"):
        self.api_key = api_key
        self.model = model

    def generate_content(self, prompt: str) -> Optional[str]:
        try:
            import requests

            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response")
        except Exception as e:
            logger.warning("Ollama generation failed: %s", e)
            return None


__all__ = ["AIProvider", "MockProvider", "GeminiProvider", "OpenAIProvider", "OllamaProvider"]
