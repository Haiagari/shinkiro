import uuid
import re
from typing import List, Optional
from src.application.ports.asset_repository import IAssetRepository
from src.application.ports.tool_provider import IToolProvider
from src.application.ports.event_bus import IEventBus
from src.application.ports.registry_client import IRegistryClient
from src.application.ports.policy_engine import IPolicyEngine
from src.domain.services.evidence_service import EvidenceService
from src.domain.models import Asset, Finding, Service
from src.domain.events import AssetDiscovered, FindingDetected

class OzyOrchestratorV10:
    """
    The 'Conductor' of the OzyRecon orchestra.
    Governs the reconnaissance workflow with strict policy and registry checks.
    """

    def __init__(
        self,
        asset_repository: IAssetRepository,
        tool_provider: IToolProvider,
        event_bus: IEventBus,
        registry_client: IRegistryClient,
        policy_engine: IPolicyEngine,
        evidence_service: EvidenceService
    ):
        self.asset_repository = asset_repository
        self.tool_provider = tool_provider
        self.event_bus = event_bus
        self.registry_client = registry_client
        self.policy_engine = policy_engine
        self.evidence_service = evidence_service

    def execute_recon(self, target: str) -> None:
        """
        Executes a full reconnaissance cycle on a target.
        1. Validates scope.
        2. Validates tool status.
        3. Executes tool.
        4. Processes findings and evidence.
        5. Persists and emits events.
        """
        # 1. Check PolicyEngine (validate scope)
        if not self.policy_engine.validate_scope(target):
            raise PermissionError(f"Target '{target}' is out of scope according to Policy Engine.")

        # 2. Check RegistryClient (validate tool status)
        tool_name = self.tool_provider.tool_name
        if not self.registry_client.is_source_approved(tool_name):
            raise RuntimeError(f"Tool '{tool_name}' is not approved by Registry Client.")

        # 3. Run ToolProvider (e.g. Nmap adapter)
        # Assuming nmap adapter returns a list of detected services/open ports
        results = self.tool_provider.execute(target, options={"service_discovery": True})

        # v10.1 Intelligence: Detect target type
        is_ip = re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target)
        target_type = "ip" if is_ip else "domain"

        # Create the base Asset (Target Seeding)
        asset = Asset(
            domain=target,
            type=target_type,
            ip=target if is_ip else None,
            is_live=True
        )
        
        # In a real scenario, we might update the asset with IP if found
        self.asset_repository.save_asset(asset)
        self.event_bus.publish(AssetDiscovered(asset=asset))

        # 4. For each service or finding found
        for result in results:
            if isinstance(result, Finding):
                finding = result
                # Ensure asset_id is the target if not set
                if not finding.asset_id:
                    finding = Finding(
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        asset_id=target,
                        evidence_ids=finding.evidence_ids,
                        vulnerability_type=finding.vulnerability_type,
                        path=finding.path,
                        param=finding.param
                    )
            elif isinstance(result, Asset):
                # If we found an asset, save it and emit event
                self.asset_repository.save_asset(result)
                self.event_bus.publish(AssetDiscovered(asset=result))
                continue
            elif isinstance(result, Service):
                service = result
                finding = Finding(
                    title=f"Service Detected: {service.service_name or 'Unknown'} on port {service.port}",
                    severity="info",
                    description=f"Detected {service.product or 'unknown service'} {service.version or ''} on {target}:{service.port}",
                    asset_id=target
                )
            else:
                # Basic mapping if it's a dict
                service = Service(
                    port=result.get("port"),
                    protocol=result.get("protocol", "tcp"),
                    service_name=result.get("service_name"),
                    product=result.get("product"),
                    version=result.get("version")
                )
                finding = Finding(
                    title=f"Service Detected: {service.service_name or 'Unknown'} on port {service.port}",
                    severity="info",
                    description=f"Detected {service.product or 'unknown service'} {service.version or ''} on {target}:{service.port}",
                    asset_id=target
                )

            # Generate signed Evidence via EvidenceService
            evidence = self.evidence_service.create_evidence(
                finding=finding,
                content={"result": result.__dict__ if hasattr(result, "__dict__") else result},
                source=tool_name
            )

            # Save to AssetRepository
            self.asset_repository.save_finding(finding)

            # Emit FindingDetected.
            self.event_bus.publish(FindingDetected(finding=finding))
