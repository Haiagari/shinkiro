"""
Modo CAMPAÑA - Escalado de Patrones
Escala un patrón específico sobre toda la base de datos histórica.
"""

import uuid
from typing import Optional, Dict, Any, List

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.export.normalizer import NormalizedExporter

logger = get_logger('mode_campaign')


class CampaignMode:
    """
    Modo CAMPAÑA - Escalado de Patrones
    
    Objetivo: Aplicar un patrón específico sobre múltiples targets.
    
    Uso típico:
    - Buscar una vulnerabilidad específica en todos los targets
    - Aplicar un nuevo template de Nuclei
    - Buscar CVEs específicos
    """
    
    def __init__(self, pattern: str, targets: Optional[List[str]] = None, options: Optional[Dict[str, Any]] = None):
        self.pattern = pattern  # CVE-ID, template, o tipo de bug
        self.targets = targets or []
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        self.context = ScanContext(
            session_id=self.session_id,
            mode="campaign"
        )
        set_context(self.context)
        
        self.db = None
        self.results = []
    
    def run(self) -> Dict[str, Any]:
        """Ejecuta la campaña."""
        logger.info(f"[CAMPAIGN] Starting campaign: {self.pattern}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            
            # Si no hay targets, obtener todos de la DB
            if not self.targets:
                all_targets = self.db.get_all_targets()
                self.targets = [t.domain for t in all_targets]
            
            logger.info(f"[CAMPAIGN] Running on {len(self.targets)} targets")
            
            for target in self.targets:
                logger.info(f"[CAMPAIGN] Scanning {target}")
                result = self._scan_target(target)
                if result:
                    self.results.append(result)
            
            self.context.mark_completed()
            
            return {
                'session_id': self.session_id,
                'pattern': self.pattern,
                'targets_scanned': len(self.targets),
                'findings': len(self.results),
                'results': self.results
            }
            
        except Exception as e:
            logger.exception(f"[CAMPAIGN] Error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _scan_target(self, target: str) -> Optional[Dict[str, Any]]:
        """Escanea un target específico con el patrón."""
        # TODO: Implementar escaneo con el patrón específico
        logger.info(f"[CAMPAIGN] Pattern {self.pattern} on {target}")
        return None


def run_campaign(pattern: str, targets: Optional[List[str]] = None, **options) -> Dict[str, Any]:
    """Función de conveniencia para modo Campaign."""
    mode = CampaignMode(pattern, targets, options)
    return mode.run()