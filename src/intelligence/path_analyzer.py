"""
PromptWall Attack Path Analyzer (v8.3.2 - Idea 1)
Simulates potential lateral movement and critical attack vectors.
"""

import logging
from typing import List, Dict, Any

from sqlalchemy import or_

from src.core.target_normalizer import normalize_lookup_target
from src.storage.models import Subdomain, Vulnerability
from src.storage.queries import DBQueries

logger = logging.getLogger("intelligence.paths")


class PathAnalyzer:
    def __init__(self, db_session):
        self.db_session = db_session
        self.db = DBQueries(db_session)

    def analyze_target_paths(self, target_domain: str) -> List[Dict[str, Any]]:
        """
        Finds logical connections between vulnerable assets and internal resources.
        """
        paths = []

        lookup_target = normalize_lookup_target(target_domain)

        # 1. Get all vulnerable hosts
        vulnerable_assets = (
            self.db_session.query(Vulnerability)
            .filter(
                or_(
                    Vulnerability.host == lookup_target,
                    Vulnerability.host.like(f"%.{lookup_target}"),
                )
            )
            .all()
        )

        vuln_hosts = list(set(v.host for v in vulnerable_assets))

        for host in vuln_hosts:
            # Find the Subdomain object to get its IP
            asset = self.db_session.query(Subdomain).filter_by(domain=host).first()
            if not asset or not asset.ip:
                continue

            # 2. Find siblings (Other hosts sharing the same IP)
            siblings = (
                self.db_session.query(Subdomain)
                .filter(Subdomain.ip == asset.ip, Subdomain.domain != host)
                .all()
            )

            if siblings:
                path = {
                    "entry_point": host,
                    "vulnerabilities": [v.name for v in vulnerable_assets if v.host == host],
                    "vector": "Shared Infrastructure (Same IP)",
                    "lateral_targets": [s.domain for s in siblings],
                    "risk_score": 80
                    if any(v.severity == "critical" for v in vulnerable_assets)
                    else 50,
                }
                paths.append(path)

            # 3. Detect Jump-Host potential (e.g. VPN, Proxy labels)
            labels = asset.semantic_labels or []
            if "role:auth" in labels or "vpn" in host:
                paths.append(
                    {
                        "entry_point": host,
                        "vector": "Logical Gateway / Authentication Surface",
                        "description": "This asset acts as an entry point to the internal network.",
                        "risk_score": 90,
                    }
                )

        return paths


# Global Instance helper
def get_attack_paths(db_session, target_domain: str):
    pa = PathAnalyzer(db_session)
    return pa.analyze_target_paths(target_domain)
