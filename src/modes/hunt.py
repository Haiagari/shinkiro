"""
Modo HUNT - Caza Agresiva basada en Capacidades
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.core.tool_manager import tool_manager
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.export.normalizer import NormalizedExporter
from src.notifications.notifier import Notifier
from src.opsec.kill_switch import check_kill
from src.utils import log, write_lines

logger = get_logger('mode_hunt')


class HuntMode:
    """
    Modo HUNT - Caza Agresiva
    Objetivo: Encontrar vulnerabilidades en targets nuevos usando capacidades abstractas.
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="hunt",
            threads=self.options.get('threads', config.threads)
        )
        set_context(self.context)
    
    def run(self) -> Dict[str, Any]:
        log.info(f"[HUNT] Starting capability-based scan on {self.target}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            self.exporter = NormalizedExporter(db_session)
            self.notifier = Notifier()
            
            # Fase 1: Discovery
            subdomains = self._discover_subdomains()
            self.context.subdomains_found = len(subdomains)
            
            if check_kill(): return self._interrupt()
            
            # Fase 2: Service Discovery & Port Scan
            services = self._scan_services(subdomains)
            self.context.ports_found = len(services)
            
            if check_kill(): return self._interrupt()
            
            # Fase 3: Vulnerability Scanning
            findings = self._scan_vulnerabilities(subdomains)
            self.context.findings = len(findings)
            
            # Export & Notify
            result = self.exporter.export_scan(self.session_id, self.target, mode="hunt")
            self.exporter.save_json(result)
            self.notifier.send_scan_summary(self.target, result)
            
            self.context.mark_completed()
            return result.to_dict()
            
        except Exception as e:
            log.exception(f"[HUNT] Critical error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}

    def _discover_subdomains(self) -> List[str]:
        log.info("[HUNT] Executing capability: asset_discovery")
        return tool_manager.run_capability("asset_discovery", self.target, all_providers=True)

    def _scan_services(self, hosts: List[str]) -> List[Any]:
        log.info("[HUNT] Executing capability: service_discovery")
        results = []
        for host in hosts[:10]: # Limitar para demo
            res = tool_manager.run_capability("service_discovery", host)
            if res: results.extend(res)
        return results

    def _scan_vulnerabilities(self, hosts: List[str]) -> List[Any]:
        log.info("[HUNT] Executing capability: template_scan")
        # Simular archivo de entrada para la capacidad
        temp_file = f"runtime/temp/hunt_{self.target}_urls.txt"
        write_lines([f"http://{h}" for h in hosts[:20]], temp_file)
        return tool_manager.run_capability("template_scan", temp_file)

    def _interrupt(self):
        self.context.mark_interrupted()
        return {'status': 'interrupted'}

def run_hunt(target: str, **options) -> Dict[str, Any]:
    return HuntMode(target, options).run()
