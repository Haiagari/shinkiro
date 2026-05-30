from typing import Any, Dict, List
from src.application.ports.tool_provider import IToolProvider
from src.domain.models import Service
from src.core.providers.nmap import NmapProvider

class NmapAdapter(IToolProvider):
    """Adapter for Nmap tool provider."""

    def __init__(self):
        self._provider = NmapProvider()

    @property
    def tool_name(self) -> str:
        return "nmap"

    def execute(self, target: str, options: Dict[str, Any]) -> List[Service]:
        """
        Executes Nmap scan and returns domain Service objects.
        
        Options can include:
        - ports: str (e.g. "80,443")
        - service_detection: bool
        - os_detection: bool
        """
        raw_results = self._provider.scan(
            host=target,
            ports=options.get("ports"),
            service_detection=options.get("service_detection", True),
            os_detection=options.get("os_detection", False),
            capability="service_discovery"
        )

        return [
            Service(
                port=r.port,
                protocol=r.protocol,
                service_name=r.service,
                product=r.product,
                version=r.version
            ) for r in raw_results
        ]
