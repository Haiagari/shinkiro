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
        from src.intelligence.pipeline.orchestrator import DiscoveryOrchestrator
        
        intent = self.get_operational_intent()
        intent["noise"] = "low"
        intent["speed"] = "slow"
        
        # 1. Discovery Orquestado (Passive + Active + Service)
        logger.info("[CONTINUOUS] Phase 1: Orchestrated Discovery")
        orchestrator = DiscoveryOrchestrator(
            self.db_session,
            scan_id=self.runtime_scan.id if self.runtime_scan else None,
        )
        scan = self.runtime_scan

        # Ejecutar fases
        orchestrator.passive_discovery(self.target)
        orchestrator.active_resolution()
        
        # 2. Calcular DIFF (basado en lo que el orquestador acaba de persistir/actualizar)
        diff_report = self.diff_engine.get_diff(self.target, scan.id)
        
        all_findings = []

        if diff_report.has_changes():
            logger.warning(f"[CONTINUOUS] Changes detected: {diff_report.summary()}")
            
            # --- NOTIFICACIÓN TELEGRAM ---
            from src.notifications.telegram import notifier
            notifier.notify_diff(self.target, diff_report)
            
            # A. Nuevos Activos -> Análisis de Servicios y Vulns
            if diff_report.new_subdomains:
                logger.info(f"[CONTINUOUS] Targeted service scan on {len(diff_report.new_subdomains)} new subdomains")
                # Aquí podríamos usar orchestrator.service_analysis() filtrando por nuevos, 
                # pero por simplicidad el orquestador ya analiza lo que está 'live'.
                # Si queremos ser EFICIENTES, el orquestador debería soportar filtros.
                orchestrator.service_analysis() 
                
                for sub in diff_report.new_subdomains:
                    # Vulns
                    v_res = tool_manager.run_capability("template_scan", sub, **intent)
                    if v_res: all_findings.extend(v_res)
            
            # B. Cambios de Versión -> Re-scan de vulns
            if diff_report.changed_services:
                logger.info(f"[CONTINUOUS] Re-scanning {len(diff_report.changed_services)} services with version changes")
                for change in diff_report.changed_services:
                    v_res = tool_manager.run_capability("template_scan", change['host'], **intent)
                    if v_res: all_findings.extend(v_res)

        else:
            logger.info("[CONTINUOUS] No changes detected. Target surface is stable.")

        # Actualizar estado final
        self._finalize_runtime_scan("completed")

        # --- EXPORT NORMALIZADO ---
        from src.export.normalizer import exporter
        result_obj = exporter.export_scan(self.session_id, self.target, mode="continuous", include_diff=True)
        export_path = exporter.save_json(result_obj)
        
        # Cleanup if temporary session (v5.4)
        if self.options.get("temp"):
            from src.workflow.engine import workflow_engine
            workflow_engine.cleanup_session(self.session_id)

        return self.build_output_envelope(
            "completed",
            has_changes=diff_report.has_changes(),
            findings_found=len(all_findings),
            export_path=str(export_path),
            include_diff=True,
        )


def run_continuous(target: str, **options) -> Dict[str, Any]:
    return ContinuousMode(target, options).run()
