"""
Modo INVESTIGACIÓN - Búsqueda Dirigida
"""

from typing import List, Dict, Any, Optional
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir, safe_filename

logger = get_logger('mode.research')

class ResearchMode(BaseMode):
    """
    Modo INVESTIGACIÓN - Búsqueda de CVEs/Tech específicos
    Inputs: target, cve_id (opcional)
    Precondiciones: Superficie conocida en DB.
    Decisiones: Filtra templates por tecnología o ID.
    """
    
    def __init__(self, target: str, cve_id: Optional[str] = None, options: Dict[str, Any] = None):
        super().__init__(target, "research", options)
        self.cve_id = cve_id

    def validate_preconditions(self):
        # Usamos DBQueries para chequear superficie
        from src.storage.queries import DBQueries
        db = DBQueries(self.db_session)
        target_obj = db.get_target(self.target)
        if not target_obj:
            raise ValueError(f"No surface known for {self.target}. Run HUNT first.")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"[RESEARCH] Investigating {self.target} (CVE: {self.cve_id or 'All'})")
        
        intent = self.get_operational_intent()
        intent["depth"] = "deep"
        
        # 1. Obtener superficie de la DB usando la sesión actual
        from src.storage.models import Subdomain
        known_assets = [s.domain for s in self.db_session.query(Subdomain).filter(
            Subdomain.is_live == 1
        ).all()]
        
        if not known_assets:
            logger.warning(f"[RESEARCH] No live assets found for {self.target}")
            return self.build_output_envelope("completed", findings_count=0, targets_scanned=0, tags_used=tags)

        # 2. Determinar tags de escaneo
        tags = []
        if self.cve_id:
            tags = [self.cve_id]
        
        # 3. Preparar archivo de targets para Nuclei
        from pathlib import Path
        temp_file = get_temp_dir() / f"research_{safe_filename(self.target)}_targets.txt"
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text("\n".join(known_assets))

        # 4. Ejecutar escaneo dirigido
        logger.info(f"[RESEARCH] Running targeted scan on {len(known_assets)} hosts")
        findings = tool_manager.run_capability("template_scan", str(temp_file), tags=tags, **intent)
        
        return self.build_output_envelope(
            "completed",
            findings_count=len(findings) if findings else 0,
            targets_scanned=len(known_assets),
            tags_used=tags,
        )

def run_research(target: str, cve_id: Optional[str] = None, **options) -> Dict[str, Any]:
    return ResearchMode(target, cve_id, options).run()
