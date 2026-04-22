"""
Modo CONTINUO - Monitoreo Diferencial
"""

from typing import List, Dict, Any
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.core.logging import get_logger

logger = get_logger('mode.continuous')

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
        target_obj = self.db.get_target(self.target)
        if not target_obj:
            logger.warning(f"Target {self.target} unknown. Establishing baseline first.")
            # Si no existe, podríamos disparar un HUNT, pero por ahora lanzamos error
            raise ValueError(f"Target {self.target} unknown. Run HUNT first.")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[CONTINUOUS] Starting monitoring cycle for {self.target}")
        from src.intelligence.learning_orchestrator import learning_orchestrator
        from src.storage.database import save_scan_to_db
        
        intent = self.get_operational_intent()
        intent["noise"] = "low"
        intent["speed"] = "slow"
        
        # 1. Discovery Ligero (Pasivo + Rápido)
        logger.info("[CONTINUOUS] Phase 1: Light Asset Discovery")
        current_subdomains = tool_manager.run_capability("asset_discovery", self.target, **intent)
        current_subdomains = list(set(current_subdomains)) if current_subdomains else []
        
        # Guardamos scan inicial para poder comparar
        db_context = {
            "target": self.target,
            "start_time": self.context.start_time.isoformat(),
            "out_dir": f"runtime/scans/{self.target}/{self.session_id}",
            "scan_status": {"status": "running", "phase": "discovery", "progress": 30},
            "phases": {
                "recon": {"all_subdomains": current_subdomains, "live_hosts": []},
                "ports": {"open_ports": []},
                "vulns": {"findings": []}
            }
        }
        save_scan_to_db(db_context)
        
        # Obtenemos el ID del scan recién creado para el DiffEngine
        target_obj = self.db.get_target(self.target)
        scan_id = self.db.query(self.db.models.Scan.id).filter(
            self.db.models.Scan.session_id == self.session_id
        ).first()[0]

        # 2. Calcular DIFF
        diff_report = self.diff_engine.get_diff(self.target, scan_id)
        
        all_findings = []
        all_services = []

        if diff_report.has_changes():
            logger.warning(f"[CONTINUOUS] Changes detected: {diff_report.summary()}")
            
            # --- NOTIFICACIÓN TELEGRAM ---
            from src.notifications.telegram import notifier
            notifier.notify_diff(self.target, diff_report)
            
            # A. Nuevos Activos -> Escaneo Completo solo a estos
            if diff_report.new_subdomains:
                logger.info(f"[CONTINUOUS] Targeted scan on {len(diff_report.new_subdomains)} new subdomains")
                for sub in diff_report.new_subdomains:
                    # Puertos
                    p_res = tool_manager.run_capability("port_scan", sub, **intent)
                    if p_res: all_services.extend(p_res)
                    # Vulns
                    v_res = tool_manager.run_capability("template_scan", sub, **intent)
                    if v_res: all_findings.extend(v_res)
            
            # B. Cambios de Versión -> Re-scan de vulns
            if diff_report.changed_services:
                logger.info(f"[CONTINUOUS] Re-scanning {len(diff_report.changed_services)} services with version changes")
                for change in diff_report.changed_services:
                    v_res = tool_manager.run_capability("template_scan", change['host'], **intent)
                    if v_res: all_findings.extend(v_res)

            # Sincronizamos con DB los resultados finales del delta
            db_context["scan_status"] = {"status": "completed", "phase": "finalized", "progress": 100}
            db_context["phases"]["ports"]["open_ports"] = all_services
            db_context["phases"]["vulns"]["findings"] = all_findings
            save_scan_to_db(db_context)

        else:
            logger.info("[CONTINUOUS] No changes detected. Target surface is stable.")

        # --- EXPORT NORMALIZADO ---
        from src.export.normalizer import exporter
        result_obj = exporter.export_scan(self.session_id, self.target, mode="continuous", include_diff=True)
        export_path = exporter.save_json(result_obj)
        
        # Cleanup if temporary session (v5.4)
        if self.options.get("temp"):
            from src.workflow.engine import workflow_engine
            workflow_engine.cleanup_session(self.session_id)

        return {
            "status": "completed",
            "session_id": self.session_id,
            "has_changes": diff_report.has_changes(),
            "findings_found": len(all_findings),
            "export_path": str(export_path)
        }


def run_continuous(target: str, **options) -> Dict[str, Any]:
    return ContinuousMode(target, options).run()
