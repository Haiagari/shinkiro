"""
Consultas Predefinidas para la Base de Datos
OzyRecon Storage Layer - Queries utilitarias.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session as DbSession

from src.storage.models import Target, Scan, Subdomain, Port, Vulnerability, Session as ScanSession, Finding, AgentMemory


class DBQueries:
    """Clase utilitaria para consultas frecuentes."""
    
    def __init__(self, db: DbSession):
        self.db = db
    
    # ══════════════════════════════════════════════════════════════════════════════
    # TARGETS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_target(self, domain: str) -> Optional[Target]:
        """Obtiene un target por dominio."""
        return self.db.query(Target).filter(Target.domain == domain).first()
    
    def get_all_targets(self, in_scope_only: bool = True) -> List[Target]:
        """Obtiene todos los targets."""
        query = self.db.query(Target)
        if in_scope_only:
            query = query.filter(Target.in_scope == 1)
        return query.order_by(Target.priority.desc(), Target.last_scan.desc()).all()
    
    def create_target(self, domain: str, **kwargs) -> Target:
        """Crea un nuevo target."""
        target = Target(domain=domain, **kwargs)
        self.db.add(target)
        self.db.commit()
        self.db.refresh(target)
        return target
    
    def update_target_technologies(self, domain: str, technologies: List[str]):
        """Actualiza las tecnologías detectadas de un target."""
        target = self.get_target(domain)
        if target:
            target.technologies = technologies
            self.db.commit()
    
    # ══════════════════════════════════════════════════════════════════════════════
    # SCANS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_scan(self, scan_id: int) -> Optional[Scan]:
        """Obtiene un scan por ID."""
        return self.db.query(Scan).get(scan_id)
    
    def get_scan_by_session(self, session_id: str) -> Optional[Scan]:
        """Obtiene un scan por session_id."""
        return self.db.query(Scan).filter(Scan.session_id == session_id).first()
    
    def get_scans_for_target(self, domain: str, limit: int = 10) -> List[Scan]:
        """Obtiene los últimos scans de un target."""
        target = self.get_target(domain)
        if not target:
            return []
        
        return self.db.query(Scan).filter(
            Scan.target_id == target.id
        ).order_by(Scan.start_time.desc()).limit(limit).all()
    
    def create_scan(self, target: str, session_id: str, mode: str = "hunt", **kwargs) -> Scan:
        """Crea un nuevo scan."""
        target_obj = self.get_target(target)
        if not target_obj:
            target_obj = self.create_target(target)
        
        scan = Scan(
            target_id=target_obj.id,
            session_id=session_id,
            mode=mode,
            timestamp=datetime.now().isoformat(),
            **kwargs
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan
    
    def update_scan_status(self, scan_id: int, status: str, **kwargs):
        """Actualiza el estado de un scan."""
        scan = self.get_scan(scan_id)
        if scan:
            scan.status = status
            for key, value in kwargs.items():
                setattr(scan, key, value)
            if status in ['completed', 'failed']:
                scan.end_time = datetime.utcnow()
            self.db.commit()
    
    # ══════════════════════════════════════════════════════════════════════════════
    # SUBDOMAINS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_live_subdomains(self, domain: str) -> List[Subdomain]:
        """Obtiene los subdominios vivos de un target."""
        target = self.get_target(domain)
        if not target:
            return []
        
        return self.db.query(Subdomain).join(Scan).filter(
            and_(
                Scan.target_id == target.id,
                Subdomain.is_live == 1
            )
        ).all()
    
    def add_subdomain(self, scan_id: int, domain: str, **kwargs) -> Subdomain:
        """Agrega un subdominio a un scan."""
        subdomain = Subdomain(scan_id=scan_id, domain=domain, **kwargs)
        self.db.add(subdomain)
        self.db.commit()
        return subdomain
    
    # ══════════════════════════════════════════════════════════════════════════════
    # PORTS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_open_ports(self, domain: str) -> List[Port]:
        """Obtiene los puertos abiertos de un target."""
        target = self.get_target(domain)
        if not target:
            return []
        
        return self.db.query(Port).join(Scan).filter(
            and_(
                Scan.target_id == target.id,
                Port.state == 'open'
            )
        ).distinct(Port.port).all()
    
    def add_port(self, scan_id: int, host: str, port: int, **kwargs) -> Port:
        """Agrega un puerto a un scan."""
        port_obj = Port(scan_id=scan_id, host=host, port=port, **kwargs)
        self.db.add(port_obj)
        self.db.commit()
        return port_obj
    
    # ══════════════════════════════════════════════════════════════════════════════
    # VULNERABILITIES
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_findings_by_severity(self, domain: str, severity: str) -> List[Vulnerability]:
        """Obtiene hallazgos por severidad."""
        target = self.get_target(domain)
        if not target:
            return []
        
        return self.db.query(Vulnerability).join(Scan).filter(
            and_(
                Scan.target_id == target.id,
                Vulnerability.severity == severity
            )
        ).all()
    
    def get_all_findings(self, domain: str) -> List[Vulnerability]:
        """Obtiene todos los hallazgos de un target."""
        target = self.get_target(domain)
        if not target:
            return []
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        findings = self.db.query(Vulnerability).join(Scan).filter(
            Scan.target_id == target.id
        ).all()
        
        # Ordenar por severidad
        findings.sort(key=lambda x: severity_order.get(x.severity, 99))
        return findings
    
    def add_vulnerability(self, scan_id: int, name: str, severity: str, **kwargs) -> Vulnerability:
        """Agrega una vulnerabilidad a un scan."""
        vuln = Vulnerability(scan_id=scan_id, name=name, severity=severity, **kwargs)
        self.db.add(vuln)
        self.db.commit()
        return vuln
    
    # ══════════════════════════════════════════════════════════════════════════════
    # SESSIONS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_session_history(self, domain: str, limit: int = 20) -> List[ScanSession]:
        """Obtiene el historial de sesiones de un target."""
        return self.db.query(ScanSession).filter(
            ScanSession.target == domain
        ).order_by(ScanSession.started_at.desc()).limit(limit).all()
    
    def create_session(self, session_id: str, target: str, mode: str) -> ScanSession:
        """Crea una nueva sesión."""
        session = ScanSession(
            session_id=session_id,
            target=target,
            mode=mode,
            status="running"
        )
        self.db.add(session)
        self.db.commit()
        return session
    
    def end_session(self, session_id: str, status: str, **kwargs):
        """Finaliza una sesión."""
        session = self.db.query(ScanSession).filter(
            ScanSession.session_id == session_id
        ).first()
        
        if session:
            session.status = status
            session.ended_at = datetime.utcnow()
            session.duration = (session.ended_at - session.started_at).total_seconds()
            
            for key, value in kwargs.items():
                setattr(session, key, value)
            
            self.db.commit()
    
    # ══════════════════════════════════════════════════════════════════════════════
    # AGENT MEMORY
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_agent_memory(self, target: str, key: str) -> Optional[AgentMemory]:
        """Obtiene memoria del agente para un target y clave."""
        return self.db.query(AgentMemory).filter(
            and_(
                AgentMemory.target == target,
                AgentMemory.key == key
            )
        ).first()
    
    def set_agent_memory(self, target: str, key: str, value: Any, mode: str = "hunt", confidence: float = 1.0):
        """Guarda memoria del agente."""
        memory = self.get_agent_memory(target, key)
        
        if memory:
            memory.value = value
            memory.confidence = confidence
            memory.created_at = datetime.utcnow()
        else:
            memory = AgentMemory(
                target=target,
                key=key,
                value=value,
                mode=mode,
                confidence=confidence
            )
            self.db.add(memory)
        
        self.db.commit()
    
    # ══════════════════════════════════════════════════════════════════════════════
    # ESTADÍSTICAS
    # ══════════════════════════════════════════════════════════════════════════════
    
    def get_target_stats(self, domain: str) -> Dict[str, Any]:
        """Obtiene estadísticas de un target."""
        target = self.get_target(domain)
        if not target:
            return {}
        
        scans = self.get_scans_for_target(domain, limit=100)
        
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.status == 'completed'])
        
        total_subdomains = sum(s.subdomains_found for s in scans)
        total_hosts = sum(s.hosts_alive for s in scans)
        total_ports = sum(s.ports_found for s in scans)
        total_findings = sum(s.findings for s in scans)
        
        return {
            'target': domain,
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'total_subdomains': total_subdomains,
            'total_hosts': total_hosts,
            'total_ports': total_ports,
            'total_findings': total_findings,
            'last_scan': scans[0].start_time.isoformat() if scans else None
        }
    
    def add_finding_intelligent(self, target: str, session_id: str, vuln_data: Dict[str, Any]) -> Finding:
        """
        Agrega un hallazgo usando inteligencia para deduplicar y trackear historial.
        """
        from src.intelligence.analyzer import Deduplicator
        dedup = Deduplicator(self.db)
        fingerprint = dedup.fingerprint(vuln_data)
        
        # Buscar si ya existe
        existing = self.db.query(Finding).filter(
            Finding.target == target,
            Finding.evidence == fingerprint
        ).first()
        
        if existing:
            existing.seen_count += 1
            existing.last_seen = datetime.utcnow()
            existing.session_id = session_id
            self.db.commit()
            return existing
        else:
            # Es un hallazgo NUEVO
            finding = Finding(
                target=target,
                session_id=session_id,
                name=vuln_data.get('name', 'Unknown'),
                type=vuln_data.get('type'),
                severity=vuln_data.get('severity', 'info'),
                host=vuln_data.get('host'),
                url=vuln_data.get('url'),
                path=vuln_data.get('path'),
                param=vuln_data.get('param'),
                description=vuln_data.get('description'),
                evidence=fingerprint, # Guardamos el hash aquí
                status="new",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                seen_count=1
            )
            self.db.add(finding)
            self.db.commit()
            self.db.refresh(finding)
            return finding
