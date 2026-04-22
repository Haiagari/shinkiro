"""
Modo SERVICIO - Reportes Ejecutivos
Genera reportes profesionales para clientes.
"""

import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.export.normalizer import NormalizedExporter

logger = get_logger('mode_service')


from src.modes.base import BaseMode
from src.core.logging import get_logger
from src.export.normalizer import exporter

logger = get_logger('mode.service')

class ServiceMode(BaseMode):
    """
    Modo SERVICIO - Generación de Reportes para Clientes
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        super().__init__(target, "servicio", options)

    def validate_preconditions(self):
        if not self.target:
            raise ValueError("Target is required for SERVICE mode")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[SERVICE] Generating executive report for client on {self.target}")
        
        # 1. Obtener el último scan del target
        target_clean = self.target
        
        # 2. Generar Export en Markdown y JSON
        from src.export.normalizer import NormalizedExporter
        exp = NormalizedExporter(self.db_session)
        
        # Obtenemos el último session_id de la DB para este target
        from src.storage.queries import DBQueries
        db_q = DBQueries(self.db_session)
        latest = db_q.get_latest_scan(target_clean)
        
        if not latest:
            logger.error(f"No scans found for {target_clean}")
            return {"status": "failed", "reason": "no_data"}

        result_obj = exp.export_scan(latest.session_id, target_clean, mode="servicio")
        
        md_path = exp.save_markdown(result_obj)
        json_path = exp.save_json(result_obj)
        
        logger.info(f"[SERVICE] Reports generated: {md_path}")
        
        return {
            "status": "completed",
            "target": self.target,
            "markdown_report": str(md_path),
            "json_report": str(json_path)
        }

def run_servicio(target: str, **options) -> Dict[str, Any]:
    return ServiceMode(target, options).run()
