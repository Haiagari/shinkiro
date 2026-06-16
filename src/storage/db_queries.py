"""
Query Helper Functions para SQLite DB
Thin delegation wrappers — all logic lives in DBQueries (queries.py).
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from .models import Scan, Subdomain, Port, Vulnerability
from .queries import DBQueries


def get_latest_scan(db: Session, target_domain: str) -> Optional[Scan]:
    q = DBQueries(db)
    return q.get_latest_scan(target_domain)


def get_scan_history(db: Session, target_domain: str, days: int = 30) -> List[Scan]:
    q = DBQueries(db)
    return q.get_scan_history(target_domain, days)


def get_new_findings(db: Session, target_domain: str, since_days: int = 7) -> List[Vulnerability]:
    q = DBQueries(db)
    return q.get_new_findings(target_domain, since_days)


def get_findings_by_severity(db: Session, severity: str) -> List[Vulnerability]:
    q = DBQueries(db)
    return q.get_all_findings_by_severity(severity)


def get_critical_findings(
    db: Session, target_domain: Optional[str] = None
) -> List[Vulnerability]:
    q = DBQueries(db)
    return q.get_critical_findings(target_domain)


def get_new_subdomains(db: Session, target_domain: str) -> List[Subdomain]:
    q = DBQueries(db)
    return q.get_new_subdomains(target_domain)


def get_new_ports(db: Session, target_domain: str) -> List[Port]:
    q = DBQueries(db)
    return q.get_new_ports(target_domain)


def get_scan_diff(db: Session, target_domain: str) -> dict:
    q = DBQueries(db)
    return q.get_scan_diff(target_domain)


def get_target_stats(db: Session, target_domain: str) -> dict:
    q = DBQueries(db)
    return q.get_target_stats(target_domain)
