"""
Modo HUNT - Caza Agresiva
Ejecuta un escaneo completo y ofensivo en targets nuevos.
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.storage.diff import DiffEngine
from src.export.normalizer import NormalizedExporter
from src.notifications.notifier import Notifier
from src.opsec.kill_switch import check_kill

logger = get_logger('mode_hunt')


class HuntMode:
    """
    Modo HUNT - Caza Agresiva
    
    Objetivo: Encontrar vulnerabilidades en targets nuevos o poco explorados.
    
    Flujo:
    1. Descubrimiento de subdominios
    2. Detección de hosts vivos
    3. Escaneo de puertos
    4. Fingerprinting de servicios
    5. Detección de vulnerabilidades
    6. Export de resultados
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        # Configuración
        self.threads = self.options.get('threads', config.threads)
        self.rate_limit = self.options.get('rate_limit', config.rate_limit)
        self.verbose = self.options.get('verbose', False)
        self.dry_run = self.options.get('dry_run', False)
        
        # Contexto de ejecución
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="hunt",
            threads=self.threads,
            rate_limit=self.rate_limit,
            verbose=self.verbose,
            dry_run=self.dry_run
        )
        set_context(self.context)
        
        # Componentes
        self.db = None
        self.exporter = None
        self.notifier = None
    
    def run(self) -> Dict[str, Any]:
        """
        Ejecuta el modo Hunt.
        
        Returns:
            Diccionario con resultados
        """
        logger.info(f"[HUNT] Starting scan on {self.target}")
        self.context.mark_running()
        
        try:
            # Inicializar DB
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            
            # Crear scan en DB
            scan = self.db.create_scan(
                target=self.target,
                session_id=self.session_id,
                mode="hunt",
                status="running"
            )
            
            # Inicializar componentes
            self.exporter = NormalizedExporter(db_session)
            self.notifier = Notifier()
            
            # Fase 1: Descubrimiento de subdominios
            logger.info("[HUNT] Phase 1: Subdomain Discovery")
            subdomains = self._discover_subdomains()
            self.context.subdomains_found = len(subdomains)
            scan.subdomains_found = len(subdomains)
            db_session.commit()
            
            if check_kill():
                self.context.mark_interrupted()
                return self._finish(scan, db_session)
            
            # Fase 2: Detección de hosts vivos
            logger.info("[HUNT] Phase 2: Live Host Detection")
            live_hosts = self._check_live_hosts(subdomains)
            self.context.hosts_alive = len(live_hosts)
            scan.hosts_alive = len(live_hosts)
            db_session.commit()
            
            if check_kill():
                self.context.mark_interrupted()
                return self._finish(scan, db_session)
            
            # Fase 3: Escaneo de puertos
            logger.info("[HUNT] Phase 3: Port Scanning")
            ports = self._scan_ports(live_hosts)
            self.context.ports_found = len(ports)
            scan.ports_found = len(ports)
            db_session.commit()
            
            if check_kill():
                self.context.mark_interrupted()
                return self._finish(scan, db_session)
            
            # Fase 4: Detección de vulnerabilidades
            logger.info("[HUNT] Phase 4: Vulnerability Detection")
            findings = self._scan_vulnerabilities(live_hosts)
            self.context.findings = len(findings)
            scan.findings = len(findings)
            db_session.commit()
            
            # Fase 5: Export
            logger.info("[HUNT] Phase 5: Export Results")
            result = self.exporter.export_scan(
                session_id=self.session_id,
                target=self.target,
                mode="hunt"
            )
            self.exporter.save_json(result)
            self.exporter.save_markdown(result)
            
            # Notificar
            self.notifier.send_scan_summary(self.target, result)
            
            # Finalizar
            self.context.mark_completed()
            self._finish(scan, db_session)
            
            logger.info(f"[HUNT] Completed. Found: {len(findings)} findings")
            
            return {
                'session_id': self.session_id,
                'target': self.target,
                'status': 'completed',
                'subdomains': len(subdomains),
                'hosts': len(live_hosts),
                'ports': len(ports),
                'findings': len(findings)
            }
            
        except Exception as e:
            logger.exception(f"[HUNT] Error: {e}")
            self.context.mark_failed(str(e))
            return {
                'session_id': self.session_id,
                'target': self.target,
                'status': 'failed',
                'error': str(e)
            }
        finally:
            if self.db:
                self.db.db.close()
    
    def _discover_subdomains(self) -> List[str]:
        """Fase 1: Descubrimiento de subdominios."""
        # TODO: Implementar con subfinder, assetfinder, crt.sh
        logger.info(f"Discovering subdomains for {self.target}")
        return []
    
    def _check_live_hosts(self, subdomains: List[str]) -> List[str]:
        """Fase 2: Detectar hosts vivos."""
        # TODO: Implementar con httpx
        logger.info(f"Checking {len(subdomains)} subdomains for liveness")
        return []
    
    def _scan_ports(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Fase 3: Escaneo de puertos."""
        # TODO: Implementar con naabu
        logger.info(f"Scanning ports on {len(hosts)} hosts")
        return []
    
    def _scan_vulnerabilities(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Fase 4: Detección de vulnerabilidades."""
        # TODO: Implementar con nuclei, dalfox
        logger.info(f"Scanning vulnerabilities on {len(hosts)} hosts")
        return []
    
    def _finish(self, scan, db_session):
        """Finaliza el scan actualizando la DB."""
        scan.status = self.context.status
        scan.end_time = datetime.now()
        db_session.commit()
        logger.info(f"[HUNT] Scan {scan.status}")


def run_hunt(target: str, **options) -> Dict[str, Any]:
    """
    Función de conveniencia para ejecutar el modo Hunt.
    
    Args:
        target: Target a escanear
        **options: Opciones adicionales
    
    Returns:
        Resultados del scan
    """
    mode = HuntMode(target, options)
    return mode.run()