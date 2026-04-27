"""
Modo HUNT - Caza Inteligente v5.0
Establece línea base y genera hipótesis para validación asistida.
"""

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.core.logging import get_logger
from src.intelligence.intelligence import run_intelligence

logger = get_logger('mode.hunt')

class HuntMode(BaseMode):
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "hunt", options)

    def validate_preconditions(self):
        if not self.target:
            raise ValueError("Target domain is required for HUNT mode")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[HUNT v5.0] Starting intelligent hunt on {self.target}")
        
        # 1. Reset Kill-Switch for a fresh run
        from src.opsec.kill_switch import kill_switch
        kill_switch.reset()
        
        # 2. OPSEC Check
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec.pre_flight_check()
        
        intent = self.get_operational_intent()
        intent.update(opsec.get_operational_params())

        # 3. Asset Discovery & Service Analysis (v6.0 Orchestrated Flow)
        logger.info("[HUNT] Discovery & Analysis Phase (Orchestrated)")
        from src.intelligence.orchestrator import DiscoveryOrchestrator
        orchestrator = DiscoveryOrchestrator(self.db_session)
        
        # Phase 1: Passive
        orchestrator.passive_discovery(self.target)
        
        # Phase 2: Active
        orchestrator.active_resolution()
        
        # Phase 3: Services
        orchestrator.service_analysis()

        # 4.5. v6.0 Logic Pattern Analysis

        logger.info("[HUNT] Phase 2.5: v6.0 Logic Pattern Analysis")
        from src.intelligence.logic_analyzer import LogicAnalyzer
        logic_brain = LogicAnalyzer()
        
        # Mapear datos para el cerebro
        graph_data = {
            "nodes": [
                {"type": "subdomain", "name": self.target, "ip": "RESOLVING..."} # Simplificado para el ejemplo
            ]
        }
        # Inyectar subdominios encontrados
        for s in subdomains:
            graph_data["nodes"].append({"type": "subdomain", "name": s, "ip": None})

        logic_hypotheses = logic_brain.analyze_graph(graph_data)
        if logic_hypotheses:
            logger.info(f"🔥 v6.0 Brain found {len(logic_hypotheses)} logical attack paths!")

        # 5. Intelligence Correlation & Hypothesis Generation
        logger.info("[HUNT] Phase 4: Intelligence & Hypothesis Generation")
        out_dir = Path(self.options.get("output") or f"runtime/scans/{self.target}/{self.session_id}")
        
        # Recuperar datos de la DB para el motor de inteligencia (ya persistidos por el orquestador)
        from src.storage.models import Subdomain, Port
        db_subdomains = self.db_session.query(Subdomain).all()
        db_ports = self.db_session.query(Port).all()
        
        intel_context = {
            "config": self.options,
            "phases": {
                "recon": {
                    "all_subdomains": [s.domain for s in db_subdomains],
                    "live_hosts": [s.domain for s in db_subdomains if s.is_live]
                },
                "ports": {
                    "open_ports": [
                        {"host": p.host, "port": p.port, "service": p.service, "version": p.version}
                        for p in db_ports
                    ]
                },
                "vulns": {"findings": []}
            }
        }
        
        # run_intelligence will handle internal persistence to Hypothesis table
        intel_results = run_intelligence(self.target, out_dir, self.options, context=intel_context)

        # 6. Final Status Update
        self.context.mark_completed()
        
        logger.info(f"[HUNT] Discovery and Intelligence phase completed.")
        logger.info(f"Generated {len(intel_results.get('hypotheses', []))} hypotheses. Run 'ozy gate list' to review.")

        return {
            "status": "completed",
            "session_id": self.session_id,
            "subdomains": len(db_subdomains),
            "hypotheses": len(intel_results.get("hypotheses", []))
        }

def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
