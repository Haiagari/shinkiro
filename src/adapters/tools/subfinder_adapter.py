from typing import Any, Dict, List
from src.application.ports.tool_provider import IToolProvider
from src.domain.models import Asset
from src.core.providers.subfinder import SubfinderProvider

class SubfinderAdapter(IToolProvider):
    """Adapter for Subfinder tool provider."""

    def __init__(self):
        self._provider = SubfinderProvider()

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def execute(self, target: str, options: Dict[str, Any]) -> List[Asset]:
        """
        Executes Subfinder and returns domain Asset objects.
        """
        raw_results = self._provider.execute(
            target,
            **options
        )

        assets = []
        for subdomain in raw_results:
            assets.append(
                Asset(
                    domain=subdomain,
                    type="subdomain",
                    is_live=False, # Need live detection to confirm
                    tags=["discovery", "subfinder"]
                )
            )
            
        return assets
