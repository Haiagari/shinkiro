from abc import ABC, abstractmethod
from typing import Any, Dict

class IRegistryClient(ABC):
    """
    Port for the External Tool/Source Registry.
    Consults which tools are available and their approved metadata.
    """

    @abstractmethod
    def get_source_metadata(self, source_id: str) -> Dict[str, Any]:
        """
        Retrieves metadata for a specific source/tool.
        Returns a dictionary with version, capability, and endpoint info.
        """
        pass

    @abstractmethod
    def is_source_approved(self, source_id: str) -> bool:
        """
        Checks if a source is approved for use in the current environment.
        """
        pass
