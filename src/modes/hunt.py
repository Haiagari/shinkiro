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
        from src.intelligence.learning_orchestrator import learning_orchestrator
        
        # 0. OPSEC: Pre-flight check
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec_check = opsec.pre_flight_check()
        
        if opsec_check.get("waf"):
            log.warning(f"[HUNT] OPSEC: WAF detected: {opsec_check['waf']['name']}")
        
        from src.intelligence.priority import PriorityEngine
        priority_engine = PriorityEngine(self.db_session)
        
        intent = self.get_operational_intent()
        intent["speed"] = "fast"
        intent["noise"] = "high"
        intent.update(opsec.get_operational_params())
        
        # 1. Discovery Total
        subdomains = tool_manager.run_capability("asset_discovery", self.target, all_providers=True, **intent)
        self.context.subdomains_found = len(subdomains)
        
        if not subdomains: return {"status": "completed", "findings": 0}

        # 2. Inteligencia: Priorización basada en Memoria + REGISTRO DE DECISIÓN
        log.info("[HUNT] Applying Intelligence: Prioritizing targets")
        prioritized_targets = priority_engine.score_hosts(self.target, subdomains)
        
        # Registramos la decisión de priorización para evaluación reflexiva
        decision_id = learning_orchestrator.record_decision(
            session_id=self.session_id,
            decision_type="prioritize_host",
            target=self.target,
            reason="historical_reputation_and_novelty",
            context={
                "total_subdomains": len(subdomains),
                "top_score": prioritized_targets[0]['score'] if prioritized_targets else 0
            }
        )
        
        # 3. Service Discovery (Siguiendo la prioridad)
        services = []
        for entry in prioritized_targets:
            host = entry['host']
            if not opsec.should_continue(): break
            
            log.info(f"[HUNT] Scanning prioritized host: {host} (Score: {entry['score']})")
            res = tool_manager.run_capability("service_discovery", host, **intent)
            if res: services.extend(res)
            
        # 4. Escaneo de Vulnerabilidades (Deep)
        sorted_hosts = [t['host'] for t in prioritized_targets]
        temp_file = f"runtime/temp/hunt_{self.target}_targets.txt"
        write_lines(sorted_hosts, temp_file)
        
        findings = tool_manager.run_capability("template_scan", temp_file, **intent)
        self.context.findings = len(findings) if findings else 0
        
        # 5. EVALUACIÓN REFLEXIVA: ¿Fue buena la decisión de priorización?
        if prioritized_targets:
            # Vemos si los hallazgos coinciden con los hosts que priorizamos
            top_host = prioritized_targets[0]['host']
            has_critical = any(f.get('severity') == 'critical' and f.get('host') == top_host for f in (findings or []))
            has_high = any(f.get('severity') == 'high' and f.get('host') == top_host for f in (findings or []))
            
            outcome = learning_orchestrator.evaluate_priority_decision(
                decision_id=decision_id,
                host=top_host,
                host_reputation=prioritized_targets[0]['score'],
                has_critical=has_critical,
                has_high=has_high,
                has_findings=any(f.get('host') == top_host for f in (findings or []))
            )
            
            # Aplicar feedback automático (ajusta pesos)
            learning_orchestrator.apply_feedback("prioritize_host", outcome)
            log.info(f"[HUNT] Learning: Outcome {outcome['result']} - Scoring weights adjusted.")

        # 6. Aprendizaje Fase 1 (Reputación)
        if findings:
            priority_engine.update_reputation(self.target, findings)
        
        return {
            "status": "completed",
            "session_id": self.session_id,
            "findings": self.context.findings,
            "intelligence_accuracy": learning_orchestrator.metrics.decision_accuracy_rate
        }


def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
