"""
Modo HUNT - Caza Agresiva
"""

from typing import List, Dict, Any
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.opsec.kill_switch import check_kill
from src.utils import log, write_lines

class HuntMode(BaseMode):
    """
    Modo HUNT - Caza Agresiva
    Inputs: target (dominio)
    Precondiciones: Ninguna (genera línea de base)
    Decisiones: Ejecuta descubrimiento total y escaneo profundo.
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "hunt", options)

    def validate_preconditions(self):
        # HUNT es el punto de entrada, no requiere datos previos
        log.info(f"[HUNT] Validating target: {self.target}")
        if not self.target:
            raise ValueError("Target domain is required for HUNT mode")

    def execute(self) -> Dict[str, Any]:
        log.info(f"[HUNT] Starting aggressive hunt on {self.target}")
        
        # 0. OPSEC: Pre-flight check - Detectar WAF y ajustar estrategia
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec_check = opsec.pre_flight_check()
        
        if opsec_check.get("waf"):
            log.warning(f"[HUNT] OPSEC: WAF detected: {opsec_check['waf']['name']} - {opsec_check.get('action', 'Rate adjusted')}")
        
        from src.intelligence.priority import PriorityEngine
        priority_engine = PriorityEngine(self.db_session)
        
        intent = self.get_operational_intent()
        intent["speed"] = "fast"
        intent["noise"] = "high"
        
        # Inyectar parámetros OPSEC
        opsec_params = opsec.get_operational_params()
        intent.update(opsec_params)
        
        # 1. Discovery Total
        subdomains = tool_manager.run_capability("asset_discovery", self.target, all_providers=True, **intent)
        self.context.subdomains_found = len(subdomains)
        
        if check_kill(): return {"status": "interrupted"}
        
        # 2. Inteligencia: Priorización basada en Memoria
        log.info("[HUNT] Applying Intelligence: Prioritizing targets based on historical memory")
        prioritized_targets = priority_engine.score_hosts(self.target, subdomains)
        
        # 3. Service Discovery (Siguiendo la prioridad + OPSEC loop)
        services = []
        for entry in prioritized_targets:
            host = entry['host']
            
            # OPSEC: Verificar si debemos continuar
            if not opsec.should_continue():
                log.warning("[HUNT] OPSEC: Kill-switch activated. Pausing scan.")
                break
            
            log.info(f"[HUNT] Scanning prioritized host: {host} (Score: {entry['score']})")
            res = tool_manager.run_capability("service_discovery", host, **intent)
            if res: services.extend(res)
            
        if check_kill(): return {"status": "interrupted"}
        
        # 4. Escaneo de Vulnerabilidades (Deep)
        # Ordenamos la lista final para el scanner
        sorted_hosts = [t['host'] for t in prioritized_targets]
        temp_file = f"runtime/temp/hunt_{self.target}_targets.txt"
        write_lines(sorted_hosts, temp_file)
        
        findings = tool_manager.run_capability("template_scan", temp_file, **intent)
        self.context.findings = len(findings) if findings else 0
        
        # 5. Aprendizaje: Actualizar memoria con lo aprendido en esta sesión
        if findings:
            log.info(f"[HUNT] Learning: Updating reputation memory with {len(findings)} findings")
            priority_engine.update_reputation(self.target, findings)
        
        return {
            "status": "completed",
            "session_id": self.session_id,
            "subdomains": len(subdomains),
            "findings": self.context.findings,
            "top_priority_host": prioritized_targets[0]['host'] if prioritized_targets else None
        }


def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
