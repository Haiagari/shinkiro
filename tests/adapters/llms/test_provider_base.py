"""Tests for the extracted AIProvider pattern (guardrail-pivot T1.1)."""

import pytest

from src.adapters.llms.provider_base import (
    AIProvider,
    GeminiProvider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
)


def test_ai_provider_is_abstract():
    """The ABC cannot be instantiated directly."""
    with pytest.raises(TypeError):
        AIProvider()


def test_mock_provider_instantiable():
    """MockProvider is the deterministic fallback provider."""
    provider = MockProvider()
    assert isinstance(provider, AIProvider)
    assert provider.generate_content("hello") is not None


def test_registry_members_present():
    """All extracted providers implement the AIProvider contract."""
    for cls in (MockProvider, GeminiProvider, OpenAIProvider, OllamaProvider):
        assert issubclass(cls, AIProvider)
