"""
Modo INVESTIGACIÓN - Búsqueda Dirigida
"""

from typing import List, Dict, Any, Optional
from src.modes.base import BaseMode
from src.core.tool_manager import tool_manager
from src.utils import log

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
        assets = self.db.get_live_subdomains(self.target)
        if not assets:
            raise ValueError(f"No surface known for {self.target}. Run HUNT first.")

    def execute(self) -> Dict[str, Any]:
        log.info(f"[RESEARCH] Investigating {self.target} (CVE: {self.cve_id or 'All'})")
        
        intent = self.get_operational_intent()
        intent["depth"] = "deep" # En investigación queremos ir al fondo
        
        # 1. Obtener superficie de la DB
        known_assets = [s.domain for s in self.db.get_live_subdomains(self.target)]
        
        # 2. Determinar tags de escaneo
        tags = []
        if self.cve_id:
            tags = [self.cve_id]
        else:
            # Recuperar tech stack de la memoria
            memory = self.db.get_agent_memory(self.target, "tech_stack")
            if memory:
                tags = memory.value
                log.info(f"[RESEARCH] Using tech stack from memory: {tags}")
            else:
                log.info("[RESEARCH] No tech stack found. Running broad tech-discovery scan.")
                # Aquí podríamos lanzar un fingerprinting primero
        
        # 3. Ejecutar escaneo dirigido
        findings = tool_manager.run_capability("template_scan", known_assets, tags=tags, **intent)
        
        return {
            "status": "completed",
            "findings_count": len(findings) if findings else 0,
            "targets_scanned": len(known_assets),
            "tags_used": tags
        }

def run_research(target: str, cve_id: Optional[str] = None, **options) -> Dict[str, Any]:
    return ResearchMode(target, cve_id, options).run()
