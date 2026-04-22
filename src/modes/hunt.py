"""
Modo HUNT - Caza Agresiva
"""

from typing import List, Dict, Any
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.opsec.kill_switch import check_kill
from src.core.logging import get_logger

logger = get_logger('mode.hunt')

class HuntMode(BaseMode):
    """
    Modo HUNT - Caza Agresiva
    Inputs: target (dominio)
    Precondiciones: Ninguna (genera línea de base)
    Decisiones: Ejecuta descubrimiento total y escaneo profundo.
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "hunt", options)
        # Aseguramos que los providers estén registrados
        from src.core.register_providers import register_all
        try:
            # register_all() # Si fuera una función, pero parece que el archivo registra al importar
            import src.core.register_providers
        except ImportError:
            logger.error("Could not register providers")

    def validate_preconditions(self):
        # HUNT es el punto de entrada, no requiere datos previos
        logger.info(f"[HUNT] Validating target: {self.target}")
        if not self.target:
            raise ValueError("Target domain is required for HUNT mode")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[HUNT] Starting aggressive hunt on {self.target}")
        from src.intelligence.learning_orchestrator import learning_orchestrator
        
        # 0. OPSEC: Pre-flight check
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec_check = opsec.pre_flight_check()
        
        if opsec_check.get("waf"):
            logger.warning(f"[HUNT] OPSEC: WAF detected: {opsec_check['waf']['name']}")
        
        from src.intelligence.priority import PriorityEngine
        priority_engine = PriorityEngine(self.db_session)
        
        intent = self.get_operational_intent()
        intent["speed"] = "fast"
        intent["noise"] = "high"
        intent.update(opsec.get_operational_params())
        
        # 1. Discovery Total - USANDO TOOL MANAGER Y PROVIDERS ABSTRAÍDOS
        logger.info(f"[HUNT] Phase 1: Asset Discovery (all providers)")
        subdomains = tool_manager.run_capability(
            "asset_discovery", 
            self.target, 
            all_providers=True, 
            opsec_manager=opsec, # PASAMOS EL MANAGER PARA EL SIGILO AUTOMÁTICO
            **intent
        )
        
        # Deduplicar resultados de múltiples providers
        subdomains = list(set(subdomains)) if subdomains else []
        self.context.subdomains_found = len(subdomains)
        logger.info(f"[HUNT] Found {len(subdomains)} total subdomains")
        
        # --- EXPORT NORMALIZADO AL FINAL ---
        # Actualizamos contadores en el contexto antes de exportar
        self.context.end_time = datetime.now()
        
        from src.export.normalizer import exporter
        from src.storage.database import save_scan_to_db
        
        # Sincronización con DB (adaptamos al formato que espera save_scan_to_db)
        db_context = {
            "target": self.target,
            "start_time": self.context.start_time.isoformat(),
            "out_dir": self.options.get("output") or f"runtime/scans/{self.target}/{self.session_id}",
            "scan_status": {"status": "completed", "phase": "finalized", "progress": 100},
            "phases": {
                "recon": {"all_subdomains": subdomains, "live_hosts": []},
                "ports": {"open_ports": services}, # Pasamos los objetos ServiceInfo/PortResult
                "vulns": {"findings": findings or []}
            }
        }
        save_scan_to_db(db_context)
        
        # Exportamos usando el normalizador pro
        # El normalizador leerá de la DB los datos que acabamos de guardar
        logger.info(f"[HUNT] Generating normalized intelligence report...")
        result_obj = exporter.export_scan(self.session_id, self.target, mode="hunt")
        export_path = exporter.save_json(result_obj)
        
        return {
            "status": "completed",
            "session_id": self.session_id,
            "findings": self.context.findings,
            "export_path": str(export_path),
            "intelligence_accuracy": learning_orchestrator.metrics.decision_accuracy_rate
        }

        }
        save_scan_to_db(db_context)
        
        # Exportamos usando el normalizador pro
        export_path = exporter.export_scan(self.session_id, self.target, mode="hunt")
        exporter.save_json(export_path)
        logger.info(f"[HUNT] Normalized export generated in runtime/exports/{self.target}/")
        
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
            if opsec and not opsec.should_continue(): break
            
            logger.info(f"[HUNT] Scanning prioritized host: {host} (Score: {entry['score']})")
            
            # USANDO CAPABILITIES DEL TOOL MANAGER
            # Primero Port Scan rápido, luego Service Discovery si hay algo abierto
            port_results = tool_manager.run_capability("port_scan", host, opsec_manager=opsec, **intent)
            
            if port_results:
                # Si encontramos puertos, intentamos identificar versiones/servicios
                ports_to_detail = ",".join([str(p.port) for p in port_results])
                logger.info(f"[HUNT] Identifying services on {host} for ports: {ports_to_detail}")
                
                svc_results = tool_manager.run_capability(
                    "service_discovery", 
                    host, 
                    ports=ports_to_detail, 
                    opsec_manager=opsec, 
                    **intent
                )
                if svc_results: services.extend(svc_results)
            
        # 4. Escaneo de Vulnerabilidades (Deep)
        # Solo escaneamos hosts vivos
        sorted_hosts = [t['host'] for t in prioritized_targets]
        if not sorted_hosts:
            logger.warning("[HUNT] No hosts to scan for vulnerabilities")
            return {"status": "completed", "findings": 0}

        temp_file = Path("runtime/temp") / f"hunt_{self.target}_targets.txt"
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text("\n".join(sorted_hosts))
        
        logger.info(f"[HUNT] Phase 4: Template-based Vulnerability Scanning")
        findings = tool_manager.run_capability("template_scan", str(temp_file), opsec_manager=opsec, **intent)
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
            logger.info(f"[HUNT] Learning: Outcome {outcome['result']} - Scoring weights adjusted.")

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
