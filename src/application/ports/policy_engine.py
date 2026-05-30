from abc import ABC, abstractmethod

class IPolicyEngine(ABC):
    """
    Port for the Policy Engine.
    Governs what OzyRecon can and cannot do based on the target and capability.
    """

    @abstractmethod
    def validate_scope(self, target: str) -> bool:
        """
        Validates if a target is within the allowed scope.
        """
        pass

    @abstractmethod
    def can_execute_capability(self, capability: str, target: str) -> bool:
        """
        Checks if a specific capability (e.g., 'brute-force', 'version-scan') 
        is allowed for the given target.
        """
        pass
