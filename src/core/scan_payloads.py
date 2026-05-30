"""Helpers for runtime scan payload assembly."""

from __future__ import annotations

from sqlalchemy.orm import Session

from src.storage.db_queries import get_latest_scan as latest_scan_query
from src.storage.models import Scan


def _format_evidence(item: object | None) -> list[dict[str, object]]:
    if item is None:
        return []
    if isinstance(item, list):
        return [_format_evidence_entry(entry) for entry in item]
    return [{"content": str(item), "type": "text"}]


def _format_evidence_entry(entry: object) -> dict[str, object]:
    if isinstance(entry, dict):
        return entry
    return {"content": str(entry), "type": "text"}


def _empty_latest_scan_payload(target_domain: str) -> dict[str, object]:
    return {
        "target": target_domain,
        "assets": [],
        "services": [],
        "findings": [],
        "stats": {
            "subdomains_found": 0,
            "hosts_alive": 0,
            "ports_found": 0,
            "findings": 0,
        },
    }


def _build_assets(latest: Scan) -> list[dict[str, object]]:
    assets = [
        {
            "value": subdomain.domain,
            "is_live": bool(subdomain.is_live),
            "ip": subdomain.ip,
            "http_status": subdomain.http_status,
            "title": subdomain.title,
            "web_server": subdomain.web_server,
            "technologies": subdomain.technologies or [],
            "semantic_labels": subdomain.semantic_labels or [],
            "business_impact": subdomain.business_impact or "LOW",
        }
        for subdomain in latest.subdomains
    ]
    return sorted(assets, key=lambda asset: (not bool(asset["is_live"]), str(asset["value"])))


def _build_services(latest: Scan) -> list[dict[str, object]]:
    return [
        {
            "host": port.host,
            "port": port.port,
            "protocol": port.protocol,
            "service": port.service,
            "state": port.state,
            "version": port.version,
            "product": port.product,
            "extra_info": port.extra_info,
            "severity": port.severity,
        }
        for port in latest.ports
    ]


def _build_findings(latest: Scan) -> list[dict[str, object]]:
    return [
        {
            "name": vuln.name,
            "type": vuln.type,
            "severity": vuln.severity,
            "host": vuln.host,
            "path": vuln.path,
            "param": vuln.param,
            "description": vuln.description,
            "evidence": _format_evidence(vuln.evidence),
            "payload": vuln.payload,
            "status": vuln.status,
        }
        for vuln in latest.vulnerabilities
    ]


def build_latest_scan_payload(db: Session, target_domain: str) -> dict[str, object]:
    """Build the normalized latest-scan payload for runtime consumers."""
    latest = latest_scan_query(db, target_domain)
    if latest is None:
        return _empty_latest_scan_payload(target_domain)

    return {
        "target": target_domain,
        "session_id": latest.session_id,
        "assets": _build_assets(latest),
        "services": _build_services(latest),
        "findings": _build_findings(latest),
        "stats": {
            "subdomains_found": latest.subdomains_found,
            "hosts_alive": latest.hosts_alive,
            "ports_found": latest.ports_found,
            "findings": latest.findings,
        },
    }


__all__ = ["build_latest_scan_payload"]
