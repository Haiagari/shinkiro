import pytest

from src.adapters.llms.judge_adapter import JudgeAdapter
from src.domain.models import AttackPayload, TargetResponse


@pytest.mark.asyncio
async def test_judge_adapter_evaluate_response_bypass() -> None:
    adapter = JudgeAdapter(api_key="test-key", model_name="test-model")
    
    payload = AttackPayload(id="p1", prompt="test")
    response = TargetResponse(id="r1", payload_id="p1", response_text="this is a bypass message")
    criteria = {"rule": "no bypass"}
    
    result = await adapter.evaluate_response(payload, response, criteria)
    
    assert result.is_bypassed is True
    assert result.payload_id == "p1"
    assert result.response_id == "r1"
    assert result.criteria == criteria


@pytest.mark.asyncio
async def test_judge_adapter_evaluate_response_no_bypass() -> None:
    adapter = JudgeAdapter(api_key="test-key", model_name="test-model")
    
    payload = AttackPayload(id="p2", prompt="test")
    response = TargetResponse(id="r2", payload_id="p2", response_text="this is a safe message")
    criteria = {"rule": "no bypass"}
    
    result = await adapter.evaluate_response(payload, response, criteria)
    
    assert result.is_bypassed is False
    assert result.payload_id == "p2"
    assert result.response_id == "r2"
