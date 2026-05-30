from abc import ABC, abstractmethod
from typing import Any, Dict, List
from src.domain.models import Asset

class IToolProvider(ABC):
    """Generic interface for security tool wrappers (nmap, subfinder, etc)."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the tool."""
        pass

    @abstractmethod
    def execute(self, target: str, options: Dict[str, Any]) -> List[Any]:
        """Executes the tool and returns a list of results."""
        pass
