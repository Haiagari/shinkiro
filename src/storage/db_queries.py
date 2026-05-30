"""
Query Helper Functions para SQLite DB
Provee funciones de consulta para diffing y reporting.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from .models import Target, Scan, Subdomain, Port, Vulnerability
from .database import SessionLocal
from src.core.target_normalizer import normalize_lookup_target


def get_latest_scan(db: Session, target_domain: str) -> Optional[Scan]:
    """
    Returns the most recent scan for a target.
    """
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return None
    return db.query(Scan).filter(Scan.target_id == target.id).order_by(Scan.id.desc()).first()


def get_scan_history(db: Session, target_domain: str, days: int = 30) -> List[Scan]:
    """
    Returns all scans within the last N days.
    """
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.start_time >= cutoff
    ).order_by(Scan.id.desc()).all()


def get_new_findings(db: Session, target_domain: str, since_days: int = 7) -> List[Vulnerability]:
    """
    Returns vulnerabilities found in the last N days.
    """
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return []
    
    # Get all scans in the period
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    recent_scans = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.start_time >= cutoff
    ).all()
    scan_ids = [s.id for s in recent_scans]
    
    if not scan_ids:
        return []
    
    # Get vulns from those scans
    vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id.in_(scan_ids)
    ).order_by(Vulnerability.severity.desc()).all()
    return vulns


def get_findings_by_severity(db: Session, severity: str) -> List[Vulnerability]:
    """
    Returns all vulnerabilities of a given severity across all targets.
    severity: 'critical', 'high', 'medium', 'low', 'info'
    """
    return db.query(Vulnerability).filter(
        Vulnerability.severity == severity.upper()
    ).order_by(Vulnerability.scan_id.desc()).all()


def get_critical_findings(db: Session, target_domain: Optional[str] = None) -> List[Vulnerability]:
    """
    Returns all critical vulnerabilities, optionally filtered by target.
    """
    query = db.query(Vulnerability).filter(Vulnerability.severity == 'CRITICAL')
    if target_domain:
        target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
        if target:
            scan_ids = [s.id for s in db.query(Scan).filter(Scan.target_id == target.id).all()]
            query = query.filter(Vulnerability.scan_id.in_(scan_ids))
    return query.order_by(Vulnerability.timestamp.desc()).all()


def get_new_subdomains(db: Session, target_domain: str) -> List[Subdomain]:
    """
    Returns subdomains not seen in previous scans.
    Returns the diff between latest scan and the one before it.
    """
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return []
    
    latest_scan = get_latest_scan(db, normalize_lookup_target(target_domain))
    if not latest_scan:
        return []
    
    # Get previous scan
    prev_scan = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.id < latest_scan.id
    ).order_by(Scan.id.desc()).first()
    
    if not prev_scan:
        # First scan - all subdomains are new
        return db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all()
    
    # Get domains from previous scan
    prev_subdomains = set(
        s.domain for s in db.query(Subdomain).filter(Subdomain.scan_id == prev_scan.id).all()
    )
    
    # Get current subdomains, filter out those that existed before
    current_subdomains = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all()
    return [s for s in current_subdomains if s.domain not in prev_subdomains]


def get_new_ports(db: Session, target_domain: str) -> List[Port]:
    """
    Returns ports not seen in previous scans.
    """
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return []
    
    latest_scan = get_latest_scan(db, normalize_lookup_target(target_domain))
    if not latest_scan:
        return []
    
    prev_scan = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.id < latest_scan.id
    ).order_by(Scan.id.desc()).first()
    
    if not prev_scan:
        return db.query(Port).filter(Port.scan_id == latest_scan.id).all()
    
    # Get previous ports as set of (host, port) tuples
    prev_ports = set(
        (p.host, p.port) for p in db.query(Port).filter(Port.scan_id == prev_scan.id).all()
    )
    
    # Filter current ports
    current_ports = db.query(Port).filter(Port.scan_id == latest_scan.id).all()
    return [p for p in current_ports if (p.host, p.port) not in prev_ports]


def get_scan_diff(db: Session, target_domain: str) -> dict:
    """
    Returns a diff dictionary comparing latest scan with previous one.
    """
    latest_scan = get_latest_scan(db, normalize_lookup_target(target_domain))
    if not latest_scan:
        return {"new_subdomains": [], "new_ports": [], "new_vulns": [], "is_first_run": True}
    
    target = db.query(Target).filter(Target.domain == normalize_lookup_target(target_domain)).first()
    if not target:
        return {"error": "Target not found"}
    
    prev_scan = db.query(Scan).filter(
        Scan.target_id == target.id,
        Scan.id < latest_scan.id
    ).order_by(Scan.id.desc()).first()
    
    if not prev_scan:
        return {
            "new_subdomains": [s.domain for s in latest_scan.subdomains],
            "new_ports": [{"host": p.host, "port": p.port} for p in latest_scan.ports],
            "new_vulns": len(latest_scan.vulnerabilities),
            "is_first_run": True
        }
    
    # Compute diff
    prev_subdomains = set(s.domain for s in prev_scan.subdomains)
    new_subs = [s for s in latest_scan.subdomains if s.domain not in prev_subdomains]
    
    prev_ports = set((p.host, p.port) for p in prev_scan.ports)
    new_ports = [p for p in latest_scan.ports if (p.host, p.port) not in prev_ports]
    
    prev_vuln_ids = set((v.type, v.url) for v in prev_scan.vulnerabilities)
    new_vulns = [v for v in latest_scan.vulnerabilities 
                 if (v.type, v.url) not in prev_vuln_ids]
    
    return {
        "new_subdomains": [{"domain": s.domain, "is_live": s.is_live} for s in new_subs],
        "new_ports": [{"host": p.host, "port": p.port, "service": p.service} for p in new_ports],
        "new_vulns": [{
            "type": v.type,
            "severity": v.severity,
            "url": v.url,
            "cve": v.cve
        } for v in new_vulns],
        "total_vulns": len(latest_scan.vulnerabilities),
        "is_first_run": False
    }


def get_target_stats(db: Session, target_domain: str) -> dict:
    """
    Returns aggregated statistics for a target.
    """
    latest_scan = get_latest_scan(db, normalize_lookup_target(target_domain))
    if not latest_scan:
        return {"error": "No scans found"}
    
    subdomains_count = len(latest_scan.subdomains)
    live_count = sum(1 for s in latest_scan.subdomains if s.is_live)
    ports_count = len(latest_scan.ports)
    
    vulns_by_severity = {}
    for v in latest_scan.vulnerabilities:
        sev = v.severity.upper()
        vulns_by_severity[sev] = vulns_by_severity.get(sev, 0) + 1
    
    return {
        "target": target_domain,
        "latest_scan_id": latest_scan.id,
        "scan_timestamp": latest_scan.timestamp,
        "total_subdomains": subdomains_count,
        "live_subdomains": live_count,
        "total_ports": ports_count,
        "vulnerabilities": vulns_by_severity,
        "critical_count": vulns_by_severity.get("CRITICAL", 0),
        "high_count": vulns_by_severity.get("HIGH", 0)
    }
