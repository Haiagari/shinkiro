import pytest

from src.adapters.llms.attacker_adapter import AttackerAdapter


@pytest.mark.asyncio
async def test_attacker_adapter_generate_payload() -> None:
    adapter = AttackerAdapter(api_key="test-key", model_name="test-model")
    
    context = {"target_url": "http://example.com"}
    previous_responses = []
    
    payload = await adapter.generate_payload(context, previous_responses)
    
    assert payload is not None
    assert payload.context == context
    assert "http://example.com" in payload.prompt
    assert "test-model" in payload.prompt
