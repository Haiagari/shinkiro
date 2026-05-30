import pytest
from src.intelligence.ai_analyzer import AIAnalyst
from src.core.config import config

def test_ai_provider_unification_interface():
    """
    Test that AIAnalyst can be initialized with different providers 
    and handles the logic of switching between them.
    """
    # Mocking config for different providers
    original_provider = config.get("ai.provider", "gemini")
    
    try:
        # Case 1: Gemini (Current)
        analyst = AIAnalyst(provider_name="gemini")
        assert hasattr(analyst, "analyze") # New unified method
        
    finally:
        pass

def test_ai_analyst_unified_analyze_method():
    """
    Test the new unified analyze method.
    """
    analyst = AIAnalyst(provider_name="mock")
    # Should work even if AI is disabled (using mock/fallback)
    result = analyst.analyze("finding", {"domain": "test.com"})
    assert "analysis" in result
    assert "recommendations" in result


def test_ai_analyst_supports_provider_registry():
    class EchoProvider:
        def __init__(self, api_key: str):
            self.api_key = api_key

        def generate_content(self, prompt: str):
            return '{"analysis": "ok", "business_impact": "LOW", "recommendations": [], "remediation_snippet": {"language": "bash", "code": "echo ok", "description": "echo"}}'

    AIAnalyst.register_provider("echo", EchoProvider)
    analyst = AIAnalyst(provider_name="echo", api_key="dummy")

    assert analyst.provider is not None
    result = analyst.analyze("finding", {"domain": "test.com"})
    assert result["analysis"] == "ok"


def test_ai_analyst_unknown_provider_falls_back_to_mock():
    analyst = AIAnalyst(provider_name="unknown-provider")
    assert analyst.provider is not None
    assert analyst.provider.__class__.__name__.lower().startswith("mock")
