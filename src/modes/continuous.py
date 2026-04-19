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
        
        intent = self.get_operational_intent()
        intent["noise"] = "low" # Queremos pasar desapercibidos
        intent["speed"] = "slow"
        
        # 1. Discovery Ligero (Pasivo)
        # En continuo solo usamos proveedores pasivos o rápidos para detectar cambios
        current_subdomains = set(tool_manager.run_capability("asset_discovery", self.target, **intent))
        
        # Necesitamos registrar este scan para poder hacer el diff
        scan_obj = self.db.create_scan(self.target, self.session_id, mode="continuous")
        
        # Guardamos subdominios encontrados para el diff
        for sub in current_subdomains:
            self.db.add_subdomain(scan_obj.id, sub)
        
        # 2. Calcular DIFF REAL usando el DiffEngine robusto
        diff_report = self.diff_engine.get_diff(self.target, scan_obj.id)
        
        if diff_report.has_changes():
            log.warn(f"[CONTINUOUS] Changes detected: {diff_report.summary()}")
            self.notifier.send_alert(
                title=f"Delta detectado: {self.target}",
                message=f"Cambios: {diff_report.summary()}"
            )
            
            # 3. ACCIÓN BASADA EN EL DIFERENCIAL (Inteligencia Reactiva)
            
            # A. Nuevos Activos -> Escaneo Completo
            if diff_report.new_subdomains:
                log.info(f"[CONTINUOUS] Reacting to NEW ASSETS: {diff_report.new_subdomains}")
                self._scan_new_assets(diff_report.new_subdomains, intent)
                
            # B. Cambios de Versión/Servicio -> Escaneo de Vulnerabilidades Específico
            if diff_report.changed_services:
                log.info(f"[CONTINUOUS] Reacting to CHANGED SERVICES: {len(diff_report.changed_services)} changes")
                for change in diff_report.changed_services:
                    host = change['host']
                    old_v = change['old']['version']
                    new_v = change['new']['version']
                    log.info(f"[CONTINUOUS] Service updated on {host}: {old_v} -> {new_v}. Triggering targeted research.")
                    # Lanzamos capacidad de escaneo de templates específica para el nuevo stack detectado
                    tool_manager.run_capability("template_scan", host, **intent)

            # C. Puertos Cerrados -> Limpieza de Memoria (Opcional)
            if diff_report.closed_ports:
                for p in diff_report.closed_ports:
                    log.info(f"[CONTINUOUS] Port {p['port']} closed on {p['host']}. Updating surface memory.")
            
            # D. Generar INTELLIGENCE BRIEF (Análisis + Recomendaciones)
            from src.intelligence.brief import generate_intelligence
            intelligence = generate_intelligence(
                self.db_session, 
                self.session_id, 
                self.target,
                diff_report.to_dict()
            )
            
            # Loggear recomendaciones accionables
            if intelligence.get("recommendations"):
                log.warning("[CONTINUOUS] INTELLIGENCE BRIEF:")
                for rec in intelligence.get("recommendations", []):
                    log.info(f"  → {rec}")
        else:
            log.info("[CONTINUOUS] No changes detected in attack surface.")

        return {
            "status": "completed",
            "has_changes": diff_report.has_changes(),
            "changes": diff_report.to_dict(),
            "intelligence": generate_intelligence(
                self.db_session,
                self.session_id,
                self.target,
                diff_report.to_dict()
            ) if diff_report.has_changes() else {}
        }

    def _scan_new_assets(self, new_assets: List[str], intent: Dict[str, Any]):
        log.info(f"[CONTINUOUS] Performing targeted scan on {len(new_assets)} new assets")
        for asset in new_assets:
            tool_manager.run_capability("service_discovery", asset, **intent)
            tool_manager.run_capability("template_scan", asset, **intent)

def run_continuous(target: str, **options) -> Dict[str, Any]:
    return ContinuousMode(target, options).run()
