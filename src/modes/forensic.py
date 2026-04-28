"""
Modo FORENSE - Análisis Post-Mortem
Análisis de brechas de detección y auto-ajuste de scoring.
"""

import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries

logger = get_logger('mode_forensic')


from src.modes.base import BaseMode
from src.core.logging import get_logger
from src.storage.queries import DBQueries

logger = get_logger('mode.forensic')

class ForensicMode(BaseMode):
    """
    Modo FORENSE - Análisis Post-Mortem
    Objetivo: Analizar brechas de detección y evolución de la superficie.
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        super().__init__(target, "forensic", options)

    def validate_preconditions(self):
        db = DBQueries(self.db_session)
        target_obj = db.get_target(self.target)
        if not target_obj:
            raise ValueError(f"No history found for {self.target}. Forensic needs a baseline.")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[FORENSIC] Deep historical analysis for {self.target}")
        
        db = DBQueries(self.db_session)
        scans = db.get_scan_history(self.target, days=365) # Historial de un año
        
        if len(scans) < 2:
            logger.warning("[FORENSIC] Limited history. Analysis might be shallow.")
        
        # 1. Análisis de Evolución de Superficie
        first_scan = scans[-1]
        latest_scan = scans[0]
        
        # 2. Análisis de Hallazgos Recurrentes vs Resueltos
        # Esto es lo que OzyAudit amará
        findings = db.query(self.db.models.Vulnerability).filter(
            self.db.models.Vulnerability.scan_id == latest_scan.id
        ).all()

        return self.build_output_envelope(
            "completed",
            total_scans_analyzed=len(scans),
            first_seen=first_scan.start_time.isoformat() if first_scan.start_time else "n/a",
            last_seen=latest_scan.start_time.isoformat() if latest_scan.start_time else "n/a",
            findings_snapshot=len(findings),
        )

def run_forensic(target: str, **options) -> Dict[str, Any]:
    return ForensicMode(target, options).run()
