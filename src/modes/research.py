"""
Modo INVESTIGACIÓN - Búsqueda de CVEs
Busca vulnerabilidades específicas en superficie conocida.
"""

import uuid
from typing import Optional, Dict, Any, List

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries

logger = get_logger('mode_research')


class ResearchMode:
    """
    Modo INVESTIGACIÓN - Búsqueda de CVEs
    
    Objetivo: Buscar CVEs específicos en tecnologías detectadas.
    
    Flujo:
    1. Obtener tech stack del target
    2. Buscar CVEs relacionados
    3. Ejecutar escaneos específicos
    """
    
    def __init__(self, target: str, cve_id: Optional[str] = None, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.cve_id = cve_id  # CVE específico o None para todos
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="research"
        )
        set_context(self.context)
        
        self.db = None
    
    def run(self) -> Dict[str, Any]:
        """Ejecuta la investigación."""
        logger.info(f"[RESEARCH] Starting research on {self.target}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            
            # Obtener tecnologías del target
            target = self.db.get_target(self.target)
            if not target:
                return {'status': 'error', 'message': 'Target not found'}
            
            technologies = target.technologies or []
            logger.info(f"[RESEARCH] Technologies: {technologies}")
            
            # Buscar CVEs relacionados
            cves = self._search_cves(technologies)
            logger.info(f"[RESEARCH] Found {len(cves)} potential CVEs")
            
            # Escuchar CVEs específicos
            if self.cve_id:
                findings = self._check_cve(self.cve_id)
            else:
                findings = self._check_cves(cves)
            
            self.context.mark_completed()
            
            return {
                'session_id': self.session_id,
                'target': self.target,
                'technologies': technologies,
                'cves_found': len(cves),
                'findings': findings
            }
            
        except Exception as e:
            logger.exception(f"[RESEARCH] Error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _search_cves(self, technologies: List[str]) -> List[Dict[str, Any]]:
        """Busca CVEs relacionados con las tecnologías."""
        # TODO: Integrar con API de CVE (cve.circl.lu, NVD, etc.)
        # Por ahora retorna lista vacía
        logger.info(f"[RESEARCH] Searching CVEs for: {technologies}")
        return []
    
    def _check_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Verifica un CVE específico."""
        # TODO: Implementar escaneo del CVE
        logger.info(f"[RESEARCH] Checking CVE: {cve_id}")
        return []
    
    def _check_cves(self, cves: List[Dict]) -> List[Dict[str, Any]]:
        """Verifica múltiples CVEs."""
        findings = []
        for cve in cves:
            result = self._check_cve(cve.get('id'))
            if result:
                findings.extend(result)
        return findings


def run_research(target: str, cve_id: Optional[str] = None, **options) -> Dict[str, Any]:
    """Función de conveniencia para modo Research."""
    mode = ResearchMode(target, cve_id, options)
    return mode.run()