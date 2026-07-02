"""
PromptWall Intelligence Generator
Produce inteligencia accionable, no solo resultados.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from src.storage.queries import DBQueries

@dataclass
class IntelligenceBrief:
    """
    Reporte de inteligencia generado vs. resultados crudos.
    """
    target: str
    session_id: str
    
    # Análisis de cambio
    surface_delta_pct: float = 0.0
    new_critical_endpoints: List[str] = field(default_factory=list)
    service_version_changes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Patrones
    vulnerability_patterns: List[Dict[str, Any]] = field(default_factory=list)
    repeated_weaknesses: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recomendaciones
    recommendations: List[str] = field(default_factory=list)
    priority_targets: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "intelligence-brief",
            "target": self.target,
            "session_id": self.session_id,
            "surface_delta_pct": self.surface_delta_pct,
            "new_critical_endpoints": self.new_critical_endpoints,
            "service_version_changes": self.service_version_changes,
            "vulnerability_patterns": self.vulnerability_patterns,
            "repeated_weaknesses": self.repeated_weaknesses,
            "recommendations": self.recommendations,
            "priority_targets": self.priority_targets,
        }

class IntelligenceGenerator:
    """
    Genera inteligencia accionable a partir de los datos crudos.
    """
    
    def __init__(self, db_session, session_id: str, target: str):
        self.db = DBQueries(db_session)
        self.session_id = session_id
        self.target = target
    
    def generate_brief(self, diff_result: Optional[Dict] = None) -> IntelligenceBrief:
        """
        Genera un Intelligence Brief completo.
        """
        brief = IntelligenceBrief(target=self.target, session_id=self.session_id)
        
        # 1. Análisis de cambio de superficie
        self._analyze_surface_delta(brief, diff_result)
        
        # 2. Detección de patrones
        self._detect_patterns(brief)
        
        # 3. Generación de recomendaciones
        self._generate_recommendations(brief)
        
        return brief
    
    def _analyze_surface_delta(self, brief: IntelligenceBrief, diff_result: Optional[Dict]):
        """Analiza el cambio en la superficie de ataque."""
        if not diff_result:
            return
        
        # Calcular delta porcentual
        new_subs = len(diff_result.get("new_subdomains", []))
        removed_subs = len(diff_result.get("removed_subdomains", []))
        
        if new_subs > 0 or removed_subs > 0:
            # Obtenemos el total de la sesión anterior
            previous_scans = self.db.get_scans_for_target(self.target, limit=2)
            if previous_scans:
                total_prev = previous_scans[0].subdomains_found or 1
                net_change = new_subs - removed_subs
                brief.surface_delta_pct = round((net_change / total_prev) * 100, 1)
        
        # Identificar endpoints críticos nuevos (contienen admin, api, internal, etc.)
        for sub in diff_result.get("new_subdomains", []):
            if any(kw in sub.lower() for kw in ["admin", "/api", "internal", "dev", "staging"]):
                brief.new_critical_endpoints.append(sub)
        
        # Cambios de versión de servicios
        for change in diff_result.get("changed_services", []):
            brief.service_version_changes.append(change)
    
    def _detect_patterns(self, brief: IntelligenceBrief):
        """Detecta patrones en los hallazgos."""
        # Obtener todos los findings de la sesión actual
        scan = self.db.get_scan_by_session(self.session_id)
        if not scan:
            return
        
        findings = scan.vulnerabilities
        
        # Agrupar por tipo
        from collections import defaultdict
        by_type = defaultdict(list)
        by_host = defaultdict(list)
        
        for f in findings:
            by_type[f.type or "unknown"].append(f)
            by_host[f.host or "unknown"].append(f)
        
        # Detectar vulnerabilidades repetidas
        for vtype, vulns in by_type.items():
            if len(vulns) >= 2:
                brief.repeated_weaknesses.append({
                    "type": vtype,
                    "count": len(vulns),
                    "affected_paths": list(set(v.path or "" for v in vulns)),
                    "severity": vulns[0].severity
                })
        
        # Generar patrones identificados
        if brief.repeated_weaknesses:
            for rw in brief.repeated_weaknesses:
                brief.vulnerability_patterns.append({
                    "pattern": f"Múltiples {rw['type']} en el mismo dominio",
                    "severity": "high" if rw['severity'] in ['critical', 'high'] else "medium",
                    "count": rw['count'],
                    "locations": rw['affected_paths'][:5]
                })
    
    def _generate_recommendations(self, brief: IntelligenceBrief):
        """Genera recomendaciones accionables."""
        recs = []
        
        # Recomendación por superficie cambiada
        if brief.surface_delta_pct > 10:
            recs.append(f"Superficie de ataque incrementado un {brief.surface_delta_pct}% desde última sesión")
        elif brief.surface_delta_pct < -10:
            recs.append("Superficie reducida - algunos activos fueron dados de baja")
        
        # Recomendación por endpoints críticos nuevos
        if brief.new_critical_endpoints:
            recs.append(f"Nuevos endpoints críticos detectados: {len(brief.new_critical_endpoints)} - revisar immediately")
        
        # Recomendación por patrones
        if brief.repeated_weaknesses:
            for pw in brief.repeated_weaknesses:
                if pw['count'] >= 3:
                    recs.append(f"Patrón detectado: {pw['count']}x {pw['type']} sugiere.vector de ataque común")
        
        # Recomendación por cambio de versiones
        for svc in brief.service_version_changes:
            recs.append(f"Servicio {svc.get('host')}:{svc.get('port')} actualizado - possible regression de seguridad")
        
        if not recs:
            recs.append("No se detectaron anomalías significativas")
        
        brief.recommendations = recs
        
        # Priorizar targets para siguientes sesiones
        brief.priority_targets = brief.new_critical_endpoints[:3]


def generate_intelligence(db_session, session_id: str, target: str, diff_result: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Función de conveniencia para generar el Intelligence Brief.
    """
    generator = IntelligenceGenerator(db_session, session_id, target)
    brief = generator.generate_brief(diff_result)
    return brief.to_dict()