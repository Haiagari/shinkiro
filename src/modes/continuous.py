"""
Modo CONTINUO - Monitoreo Continuo
Ejecuta escaneos periódicos y alerta sobre cambios.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.storage.diff import DiffEngine
from src.export.normalizer import NormalizedExporter
from src.notifications.notifier import Notifier
from src.opsec.kill_switch import check_kill

logger = get_logger('mode_continuous')


class ContinuousMode:
    """
    Modo CONTINUO - Monitoreo 24/7
    
    Objetivo: Detectar cambios en targets ya conocidos.
    
    Flujo:
    1. Obtener último snapshot
    2. Ejecutar escaneo ligero
    3. Comparar con snapshot anterior
    4. Alertar solo si hay cambios (nuevos subdominios, puertos, hallazgos)
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        # Configuración
        self.interval = self.options.get('interval', 3600)  # 1 hora por defecto
        self.alert_on_change = self.options.get('alert_on_change', True)
        
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="continuous"
        )
        set_context(self.context)
        
        self.db = None
        self.diff_engine = None
        self.notifier = None
    
    def run(self) -> Dict[str, Any]:
        """Ejecuta un ciclo de monitoreo."""
        logger.info(f"[CONTINUOUS] Starting monitoring on {self.target}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            self.diff_engine = DiffEngine(db_session)
            self.notifier = Notifier()
            
            # Obtener último scan para comparar
            previous_scans = self.db.get_scans_for_target(self.target, limit=1)
            previous_scan = previous_scans[0] if previous_scans else None
            
            # Ejecutar escaneo ligero
            logger.info("[CONTINUOUS] Running lightweight scan")
            scan = self._lightweight_scan(db_session)
            
            # Comparar con scan anterior
            if previous_scan:
                logger.info("[CONTINUOUS] Computing diff with previous scan")
                diff = self.diff_engine.compute_diff(scan.id, previous_scan.id)
                
                # Alertar si hay cambios significativos
                if diff.has_changes() and self.alert_on_change:
                    self.notifier.send_alert(
                        title=f"Cambios detectados en {self.target}",
                        message=f"Nuevos hallazgos: {diff.summary()}"
                    )
            
            self.context.mark_completed()
            return {
                'session_id': self.session_id,
                'target': self.target,
                'status': 'completed',
                'has_changes': diff.has_changes() if previous_scan else True
            }
            
        except Exception as e:
            logger.exception(f"[CONTINUOUS] Error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _lightweight_scan(self, db_session) -> Any:
        """Escaneo ligero para monitoreo."""
        # Solo subdomains y puertos básicos
        # TODO: Implementar
        logger.info("[CONTINUOUS] Lightweight scan not yet implemented")
        return None


def run_continuous(target: str, **options) -> Dict[str, Any]:
    """Función de conveniencia para modo Continuous."""
    mode = ContinuousMode(target, options)
    return mode.run()