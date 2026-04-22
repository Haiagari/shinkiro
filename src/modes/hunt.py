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
        
        # Reset Kill-Switch
        from src.opsec.kill_switch import kill_switch
        kill_switch.reset()
        
        # 0. OPSEC Check
        from src.opsec.manager import OPSECManager
        opsec = OPSECManager(self.target, self.db_session)
        opsec.pre_flight_check()
        
        intent = self.get_operational_intent()
        intent.update(opsec.get_operational_params())

        # 1. Asset Discovery
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

        # 2. Ports & Services (Línea base rápida para inteligencia)
        # Nota: En v5.0 esto alimenta las hipótesis
        logger.info("[HUNT] Phase 2: Rapid Service Discovery")
        services = []
        # Escaneamos solo el target principal y un par de subs críticos para no demorar el demo
        targets_to_scan = [self.target] + subdomains[:3] 
        for host in targets_to_scan:
            res = tool_manager.run_capability("port_scan", host, opsec_manager=opsec, **intent)
            if res:
                logger.info(f"  • Found {len(res)} ports on {host}")
                services.extend(res)

        # 3. Intelligence Correlation & Hypothesis Generation
        logger.info("[HUNT] Phase 3: Intelligence & Hypothesis Generation")
        out_dir = Path(self.options.get("output") or f"runtime/scans/{self.target}/{self.session_id}")
        
        # Preparamos el contexto para el motor de inteligencia
        intel_context = {
            "config": self.options,
            "phases": {
                "recon": {"all_subdomains": subdomains, "live_hosts": targets_to_scan},
                "ports": {"open_ports": services},
                "vulns": {"findings": []}
            }
        }

        }
        
        print(">>> DEBUG: Calling run_intelligence")
        try:
            intel_results = run_intelligence(self.target, out_dir, self.options, context=intel_context)
            print(">>> DEBUG: run_intelligence finished")
        except Exception as e:
            print(f">>> DEBUG: run_intelligence crashed: {str(e)}")
            import traceback
            traceback.print_exc()
            intel_results = {"hypotheses": []}

        print(">>> DEBUG: Finishing execute")
        return {
            "status": "completed",
            "session_id": self.session_id,
            "hypotheses_count": len(intel_results.get("hypotheses", [])),
            "subdomains": 0
        }

def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
