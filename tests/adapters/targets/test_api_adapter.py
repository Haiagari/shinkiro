import pytest

from src.adapters.targets.api_adapter import TargetAPIAdapter
from src.domain.models import AttackPayload


@pytest.mark.asyncio
async def test_target_api_adapter_send_prompt() -> None:
    adapter = TargetAPIAdapter(endpoint_url="http://test.local", api_key="test-key")
    
    payload = AttackPayload(id="p1", prompt="test prompt")
    
    response = await adapter.send_prompt(payload)
    
    assert response is not None
    assert response.payload_id == "p1"
    assert "http://test.local" in response.response_text
    assert "p1" in response.response_text
