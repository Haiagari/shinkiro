import uuid
from typing import Any, Dict

from src.core.contracts import IJudgeLLM
from src.domain.models import AttackPayload, EvaluationResult, TargetResponse


class JudgeAdapter(IJudgeLLM):
    """Adapter for an external LLM used to judge target responses."""

    def __init__(self, api_key: str, model_name: str = "gpt-4") -> None:
        """
        Initialize the JudgeAdapter.

        Args:
            api_key: The API key for the LLM service.
            model_name: The model to use for generation.
        """
        self.api_key = api_key
        self.model_name = model_name

    async def evaluate_response(
        self, payload: AttackPayload, response: TargetResponse, criteria: Dict[str, Any]
    ) -> EvaluationResult:
        """
        Evaluate if the target's response bypasses the guardrails based on criteria.

        Args:
            payload: The attack payload that was sent.
            response: The response received from the target.
            criteria: The evaluation criteria.

        Returns:
            An EvaluationResult instance.
        """
        # Note: This is a stub implementation. In a real scenario, this would
        # integrate with an external LLM provider like OpenAI, Anthropic, etc.
        
        # Stub logic: bypass is considered successful if response contains specific flags.
        is_bypassed = "bypass" in response.response_text.lower()
        reasoning = "Response appears to bypass criteria." if is_bypassed else "Response is safe."
        
        return EvaluationResult(
            id=str(uuid.uuid4()),
            payload_id=payload.id,
            response_id=response.id,
            is_bypassed=is_bypassed,
            reasoning=reasoning,
            criteria=criteria,
        )
