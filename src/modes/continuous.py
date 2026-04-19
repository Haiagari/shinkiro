"""
Modo CONTINUO - Monitoreo Diferencial
"""

from typing import List, Dict, Any
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.utils import log

class ContinuousMode(BaseMode):
    """
    Modo CONTINUO - Monitoreo 24/7
    Inputs: target (ya conocido)
    Precondiciones: Debe existir un scan previo exitoso.
    Decisiones: Solo actúa sobre el delta (novedades).
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "continuous", options)

    def validate_preconditions(self):
        # Necesitamos saber si ya conocemos este target
        target_obj = self.db.get_target(self.target)
        if not target_obj:
            raise ValueError(f"Target {self.target} unknown. Run HUNT first to establish baseline.")

    def execute(self) -> Dict[str, Any]:
        log.info(f"[CONTINUOUS] Starting monitoring cycle for {self.target}")
        from src.intelligence.learning_orchestrator import learning_orchestrator
        
        intent = self.get_operational_intent()
        intent["noise"] = "low"
        intent["speed"] = "slow"
        
        # 1. Discovery Ligero
        current_subdomains = set(tool_manager.run_capability("asset_discovery", self.target, **intent))
        scan_obj = self.db.create_scan(self.target, self.session_id, mode="continuous")
        for sub in current_subdomains:
            self.db.add_subdomain(scan_obj.id, sub)
        
        # 2. Calcular DIFF
        diff_report = self.diff_engine.get_diff(self.target, scan_obj.id)
        
        findings = []
        if diff_report.has_changes():
            log.warn(f"[CONTINUOUS] Changes detected: {diff_report.summary()}")
            
            # REGISTRO DE DECISIÓN: Disparar escaneo por diferencia
            decision_id = learning_orchestrator.record_decision(
                session_id=self.session_id,
                decision_type="trigger_scan_on_diff",
                target=self.target,
                reason="changes_detected_in_surface",
                context=diff_report.to_dict()
            )
            
            # A. Nuevos Activos
            if diff_report.new_subdomains:
                new_findings = self._scan_new_assets(diff_report.new_subdomains, intent)
                if new_findings: findings.extend(new_findings)
                
            # B. Cambios de Versión
            if diff_report.changed_services:
                for change in diff_report.changed_services:
                    host = change['host']
                    res = tool_manager.run_capability("template_scan", host, **intent)
                    if res: findings.extend(res)

            # C. Puertos Cerrados
            if diff_report.closed_ports:
                for p in diff_report.closed_ports:
                    log.info(f"[CONTINUOUS] Port {p['port']} closed on {p['host']}")

            # EVALUACIÓN REFLEXIVA: ¿Sirvió de algo escanear el delta?
            outcome = learning_orchestrator.evaluate_decision(
                decision_id=decision_id,
                findings=findings,
                time_spent=60.0 # Estimado
            )
            learning_orchestrator.apply_feedback("trigger_scan_on_diff", outcome)
            log.info(f"[CONTINUOUS] Learning: Delta scan outcome: {outcome['result']}")

        return {
            "status": "completed",
            "has_changes": diff_report.has_changes(),
            "findings_found": len(findings),
            "intelligence": learning_orchestrator.get_full_feedback()
        }

    def _scan_new_assets(self, new_assets: List[str], intent: Dict[str, Any]) -> List[Any]:
        log.info(f"[CONTINUOUS] Performing targeted scan on {len(new_assets)} new assets")
        all_findings = []
        for asset in new_assets:
            tool_manager.run_capability("service_discovery", asset, **intent)
            res = tool_manager.run_capability("template_scan", asset, **intent)
            if res: all_findings.extend(res)
        return all_findings

def run_continuous(target: str, **options) -> Dict[str, Any]:
    return ContinuousMode(target, options).run()
