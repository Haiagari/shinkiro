import logging
from typing import Optional

from src.core.contracts import IJudgeLLM, ITargetAPI
from src.application.ports.event_bus import IEventBus
from src.domain.events import PromptReceived, AttackBlocked, TargetResponded
from src.domain.models import AttackPayload, TargetResponse

logger = logging.getLogger(__name__)

class AIOrchestrator:
    """
    Defensive Firewall Orchestrator for AI interactions.
    Intercepts incoming prompts, uses a judge to evaluate them for malicious intents,
    and forwards safe prompts to the target API.
    """
    def __init__(
        self,
        judge_llm: IJudgeLLM,
        target_api: ITargetAPI,
        event_bus: IEventBus
    ):
        self.judge_llm = judge_llm
        self.target_api = target_api
        self.event_bus = event_bus

    async def process_prompt(self, payload: AttackPayload) -> Optional[TargetResponse]:
        """
        The AI Security Guardrail loop:
        1. Intercept incoming prompt from user/client (publish PromptReceived).
        2. Use IJudgeLLM to evaluate the raw prompt for malicious intents, prompt injections, or jailbreaks.
        3. If Judge flags it as malicious, block it, publish AttackBlocked, and log the telemetry.
        4. If Judge approves it, use ITargetAPI to safely forward the prompt to the upstream LLM and return the response.
        """
        # Step 1: Intercept incoming prompt
        logger.info(f"Intercepted prompt: {payload.id}")
        self.event_bus.publish(PromptReceived(payload=payload))

        # Step 2: Use IJudgeLLM to evaluate the raw prompt
        logger.info(f"Evaluating prompt: {payload.id}")
        evaluation = await self.judge_llm.evaluate_prompt(payload)

        # Step 3: If Judge flags it as malicious
        if evaluation.is_bypassed:
            logger.warning(f"Prompt blocked by firewall: {evaluation.reasoning}")
            self.event_bus.publish(AttackBlocked(payload=payload, reason=evaluation.reasoning))
            return None

        # Step 4: If safe, use ITargetAPI to safely forward
        logger.info(f"Prompt approved. Forwarding to Target API: {payload.id}")
        response = await self.target_api.send_prompt(payload)
        
        self.event_bus.publish(TargetResponded(response=response))
        return response
