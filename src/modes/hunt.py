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
from src.storage.database import save_scan_to_db

logger = get_logger('mode.hunt')

class HuntMode(BaseMode):
    def __init__(self, target: str, options: Dict[str, Any] = None):
        super().__init__(target, "hunt", options)
        # Asegurar registro de providers
        import src.core.register_providers

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

        # 3. Asset Discovery
        logger.info("[HUNT] Phase 1: Asset Discovery")
        subdomains = tool_manager.run_capability(
            "asset_discovery", 
            self.target, 
            all_providers=True, 
            opsec_manager=opsec,
            **intent
        )
        subdomains = list(set(subdomains)) if subdomains else []
        self.context.subdomains_found = len(subdomains)
        logger.info(f"[HUNT] Found {len(subdomains)} subdomains")

        # 4. Rapid Service Discovery (Feeding the Intelligence engine)
        logger.info("[HUNT] Phase 2: Rapid Service Discovery")
        services = []
        # Focus on top candidates to ensure performance
        targets_to_scan = [self.target] + subdomains[:5] 
        for host in targets_to_scan:
            res = tool_manager.run_capability("port_scan", host, opsec_manager=opsec, **intent)
            if res:
                logger.info(f"  • Found {len(res)} open ports on {host}")
                services.extend(res)

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
        logger.info("[HUNT] Phase 3: Intelligence & Hypothesis Generation")
        out_dir = Path(self.options.get("output") or f"runtime/scans/{self.target}/{self.session_id}")
        
        intel_context = {
            "config": self.options,
            "phases": {
                "recon": {"all_subdomains": subdomains, "live_hosts": targets_to_scan},
                "ports": {"open_ports": services},
                "vulns": {"findings": []}
            }
        }
        
        # run_intelligence will handle internal persistence to Hypothesis table
        intel_results = run_intelligence(self.target, out_dir, self.options, context=intel_context)

        # 6. Final Persistence (Scan & Findings tables)
        self.context.mark_completed()
        db_context = {
            "target": self.target,
            "start_time": self.context.started_at.isoformat(),
            "out_dir": str(out_dir),
            "scan_status": {"status": "completed", "phase": "intelligence_ready", "progress": 100},
            "phases": intel_context["phases"]
        }
        save_scan_to_db(db_context)

        logger.info(f"[HUNT] Discovery and Intelligence phase completed.")
        logger.info(f"Generated {len(intel_results.get('hypotheses', []))} hypotheses. Run 'ozy gate list' to review.")

        # Cleanup if temporary session (v5.4)
        if self.options.get("temp"):
            logger.warning(f"[HUNT] Cleaning up temporary session data for {self.session_id}...")
            workflow_engine.cleanup_session(self.session_id)

        return {
            "status": "completed",
            "session_id": self.session_id,
            "subdomains": len(subdomains),
            "hypotheses": len(intel_results.get("hypotheses", []))
        }

def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
