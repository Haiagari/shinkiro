"""
OzyRecon Diff Engine - Inteligencia Diferencial
Compara estados entre ejecuciones para detectar cambios en la superficie de ataque.
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from src.core.logging import get_logger

logger = get_logger('diff_engine')

@dataclass
class DiffReport:
    """Reporte estructurado de cambios detectados."""
    target: str
    new_subdomains: List[str] = field(default_factory=list)
    removed_subdomains: List[str] = field(default_factory=list)
    changed_subdomains: List[Dict[str, Any]] = field(default_factory=list)
    new_ports: List[Dict[str, Any]] = field(default_factory=list)
    closed_ports: List[Dict[str, Any]] = field(default_factory=list)
    changed_services: List[Dict[str, Any]] = field(default_factory=list)
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    
    def has_changes(self) -> bool:
        return any([
            self.new_subdomains, self.removed_subdomains, self.changed_subdomains,
            self.new_ports, self.closed_ports,
            self.changed_services, self.new_findings
        ])
    
    def summary(self) -> str:
        parts = []
        if self.new_subdomains: parts.append(f"+{len(self.new_subdomains)} subdomains")
        if self.changed_subdomains: parts.append(f"*{len(self.changed_subdomains)} metadata changes")
        if self.new_ports: parts.append(f"+{len(self.new_ports)} ports")
        if self.changed_services: parts.append(f"*{len(self.changed_services)} services")
        if self.new_findings: parts.append(f"!{len(self.new_findings)} findings")
        return ", ".join(parts) or "No changes detected"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class DiffEngine:
    """Motor de cálculo de diferencias entre estados persistidos."""
    
    def __init__(self, db_session):
        self.db = db_session

    def get_diff(self, target: str, current_scan_id: int, previous_scan_id: Optional[int] = None) -> DiffReport:
        """
        Compara el scan actual con uno anterior.
        Si previous_scan_id es None, busca el último exitoso para ese target.
        """
        if not previous_scan_id:
            previous_scan_id = self._get_last_successful_scan_id(target, current_scan_id)
        
        report = DiffReport(target=target)
        
        if not previous_scan_id:
            logger.info(f"No previous scan found for {target}. First run.")
            return report

        # 1. Comparar Subdominios
        self._diff_subdomains(current_scan_id, previous_scan_id, report)
        
        # 2. Comparar Puertos y Servicios
        self._diff_ports(current_scan_id, previous_scan_id, report)
        
        # 3. Comparar Hallazgos
        self._diff_findings(current_scan_id, previous_scan_id, report)
        
        return report

    def _get_last_successful_scan_id(self, target: str, current_id: int) -> Optional[int]:
        from src.storage.models import Scan, Target
        res = self.db.query(Scan.id).join(Target).filter(
            Target.domain == target,
            Scan.id < current_id,
            Scan.status == 'completed'
        ).order_by(Scan.id.desc()).first()
        return res[0] if res else None

    def _diff_subdomains(self, curr_id: int, prev_id: int, report: DiffReport):
        from src.storage.models import Subdomain
        curr_objs = self.db.query(Subdomain).filter(Subdomain.scan_id == curr_id).all()
        prev_objs = self.db.query(Subdomain).filter(Subdomain.scan_id == prev_id).all()
        
        curr_map = {s.domain: s for s in curr_objs}
        prev_map = {s.domain: s for s in prev_objs}
        
        curr_set = set(curr_map.keys())
        prev_set = set(prev_map.keys())
        
        report.new_subdomains = list(curr_set - prev_set)
        report.removed_subdomains = list(prev_set - curr_set)

        # Detectar cambios en metadatos para dominios existentes
        for domain in (curr_set & prev_set):
            c = curr_map[domain]
            p = prev_map[domain]
            
            changes = {}
            if c.ip != p.ip: changes["ip"] = {"old": p.ip, "new": c.ip}
            if c.title != p.title: changes["title"] = {"old": p.title, "new": c.title}
            if c.asn != p.asn: changes["asn"] = {"old": p.asn, "new": c.asn}
            if c.cloud_provider != p.cloud_provider: changes["cloud"] = {"old": p.cloud_provider, "new": c.cloud_provider}
            
            # Comparar tecnologías (listas)
            c_tech = set(c.technologies or [])
            p_tech = set(p.technologies or [])
            if c_tech != p_tech:
                changes["technologies"] = {
                    "added": list(c_tech - p_tech),
                    "removed": list(p_tech - c_tech)
                }

            if changes:
                report.changed_subdomains.append({
                    "domain": domain,
                    "changes": changes
                })

    def _diff_ports(self, curr_id: int, prev_id: int, report: DiffReport):
        from src.storage.models import Port
        curr_ports = self.db.query(Port).filter(Port.scan_id == curr_id).all()
        prev_ports = self.db.query(Port).filter(Port.scan_id == prev_id).all()
        
        curr_map = {(p.host, p.port): p for p in curr_ports}
        prev_map = {(p.host, p.port): p for p in prev_ports}
        
        curr_keys = set(curr_map.keys())
        prev_keys = set(prev_map.keys())
        
        # Nuevos puertos
        for k in (curr_keys - prev_keys):
            p = curr_map[k]
            report.new_ports.append({"host": p.host, "port": p.port, "service": p.service})
            
        # Puertos cerrados
        for k in (prev_keys - curr_keys):
            p = prev_map[k]
            report.closed_ports.append({"host": p.host, "port": p.port})
            
        # Cambios en servicios/banners
        for k in (curr_keys & prev_keys):
            cp = curr_map[k]
            pp = prev_map[k]
            if cp.version != pp.version or cp.product != pp.product or cp.service != pp.service:
                report.changed_services.append({
                    "host": cp.host,
                    "port": cp.port,
                    "old": {"service": pp.service, "version": pp.version},
                    "new": {"service": cp.service, "version": cp.version}
                })

    def _diff_findings(self, curr_id: int, prev_id: int, report: DiffReport):
        from src.storage.models import Vulnerability
        curr_vulns = {v.name + v.host + (v.path or "") for v in self.db.query(Vulnerability).filter(Vulnerability.scan_id == curr_id).all()}
        prev_vulns = {v.name + v.host + (v.path or "") for v in self.db.query(Vulnerability).filter(Vulnerability.scan_id == prev_id).all()}
        
        # Simplificación: usamos un hash de nombre+host+path para detectar nuevos
        # En una implementación real usaríamos un ID único de hallazgo
        report.new_findings = list(curr_vulns - prev_vulns)
