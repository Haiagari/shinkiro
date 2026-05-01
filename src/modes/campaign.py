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
from src.core.runtime_paths import get_temp_dir

logger = get_logger('mode_campaign')


from src.modes.base import BaseMode
from src.core.logging import get_logger
from src.core.tool_manager import tool_manager
from pathlib import Path

logger = get_logger('mode.campaign')

class CampaignMode(BaseMode):
    """
    Modo CAMPAÑA - Escalado de Patrones Masivo
    Inputs: pattern (CVE/Tag), targets (lista de dominios)
    """
    
    def __init__(self, targets: List[str], pattern: str, options: Optional[Dict[str, Any]] = None):
        # Usamos el primer target como referencia para el BaseMode, pero manejamos múltiples
        super().__init__(targets[0] if targets else "multi-target", "campaign", options)
        self.targets = targets
        self.pattern = pattern
    
    def validate_preconditions(self):
        if not self.pattern:
            raise ValueError("Pattern (CVE ID or Nuclei Tag) is required for CAMPAIGN mode")
        if not self.targets:
            raise ValueError("At least one target is required for CAMPAIGN mode")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[CAMPAIGN] Starting pattern escalation: {self.pattern} on {len(self.targets)} targets")
        
        intent = self.get_operational_intent()
        intent["tags"] = [self.pattern]
        intent["speed"] = "fast"
        
        # 1. Preparar lista de targets
        temp_file = get_temp_dir() / f"campaign_{self.session_id}_targets.txt"
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text("\n".join(self.targets))
        
        # 2. Ejecutar escaneo masivo con Nuclei
        logger.info(f"[CAMPAIGN] Running mass scan across targets...")
        findings = tool_manager.run_capability("template_scan", str(temp_file), **intent)
        
        # 3. Notificar hallazgos críticos de inmediato
        if findings:
            from src.notifications.telegram import notifier
            critical_count = sum(1 for f in findings if f.get('info', {}).get('severity', '').lower() in ['critical', 'high'])
            if critical_count > 0:
                notifier.send_message(f"🔥 *CAMPAIGN ALERT*\nPattern: `{self.pattern}`\nFindings: `{len(findings)}` total\nCritical/High: `{critical_count}`")

        return self.build_output_envelope(
            "completed",
            pattern=self.pattern,
            targets_count=len(self.targets),
            findings_found=len(findings) if findings else 0,
        )

def run_campaign(target: str, pattern: str = "", **options) -> Dict[str, Any]:
    return CampaignMode(target, pattern, options).run()
