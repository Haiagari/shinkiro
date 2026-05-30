from typing import Any, Dict, List
from src.application.ports.tool_provider import IToolProvider
from src.domain.models import Finding
from src.core.providers.nuclei import NucleiProvider

class NucleiAdapter(IToolProvider):
    """Adapter for Nuclei tool provider."""

    def __init__(self):
        self._provider = NucleiProvider()

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def execute(self, target: str, options: Dict[str, Any]) -> List[Finding]:
        """
        Executes Nuclei scan and returns domain Finding objects.
        """
        raw_results = self._provider.execute(
            target,
            **options
        )

        findings = []
        for r in raw_results:
            # Nuclei result structure: template-id, info (name, severity, description), etc.
            info = r.get("info", {})
            finding = Finding(
                title=info.get("name", r.get("template-id")),
                severity=info.get("severity", "info").lower(),
                description=info.get("description", "No description provided"),
                asset_id=r.get("host", target),
                vulnerability_type=info.get("classification", {}).get("cwe-id"),
                path=r.get("matched-at"),
                evidence_ids=[] # Will be linked by evidence service
            )
            findings.append(finding)
            
        return findings
