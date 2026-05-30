from src.application.ports.policy_engine import IPolicyEngine
from src.validation.policy import ValidationPolicy

class OzyPolicyAdapter(IPolicyEngine):
    """
    Policy Engine Adapter.
    Bridges OzyRecon's internal ValidationPolicy to the Governed Citizen port.
    """

    def __init__(self, policy: ValidationPolicy = None):
        self.policy = policy or ValidationPolicy()

    def validate_scope(self, target: str) -> bool:
        decision = self.policy.scope_decision(target)
        return decision.is_safe or decision.requires_gate

    def can_execute_capability(self, capability: str, target: str) -> bool:
        # Check scope first
        if not self.validate_scope(target):
            return False
            
        # Wrap hypothesis-like classification for the capability
        # In this context, we treat the capability as a type to check against policy
        hypothesis = {
            "type": capability,
            "url": target
        }
        decision = self.policy.classify(hypothesis)
        
        # In a governed citizen context, we only allow what is 'safe' 
        # or 'gate_required' if it's explicitly allowed. 
        # For the port's boolean check, we return True if not 'blocked'.
        return not decision.is_blocked
