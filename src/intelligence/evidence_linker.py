"""
Evidence Linker Module (v9.0.1)
Provides correlation between assets, services, vulnerabilities, and their evidence sources.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class EvidenceLink:
    """
    Represents a correlation between a finding and its evidence source.
    """
    finding_id: str = ""
    finding_type: str = ""
    finding_host: str = ""
    evidence_id: str = ""
    evidence_source: str = ""
    evidence_type: str = ""
    confidence: str = ""
    timestamp: str = ""
    raw_evidence: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.raw_evidence is None:
            self.raw_evidence = {}


class EvidenceLinker:
    """
    Links findings to their evidence sources for traceability.
    """
    
    def __init__(self):
        self.links: List[EvidenceLink] = []
    
    def link_subdomain_to_httpx(
        self,
        domain: str,
        http_status: int,
        technologies: List[str],
        timestamp: str,
    ) -> EvidenceLink:
        """
        Links a subdomain to its HTTP probing evidence.
        """
        link = EvidenceLink(
            finding_id=f"sub_{domain}",
            finding_type="subdomain",
            finding_host=domain,
            evidence_id=f"httpx_{domain}_{timestamp}",
            evidence_source="httpx",
            evidence_type="http_response",
            confidence="high" if http_status else "medium",
            timestamp=timestamp,
            raw_evidence={
                "status_code": http_status,
                "technologies": technologies,
            }
        )
        self.links.append(link)
        return link
    
    def link_port_to_nmap(
        self,
        host: str,
        port: int,
        service: str,
        version: Optional[str],
        timestamp: str,
    ) -> EvidenceLink:
        """
        Links a port to its nmap evidence.
        """
        link = EvidenceLink(
            finding_id=f"port_{host}_{port}",
            finding_type="port",
            finding_host=host,
            evidence_id=f"nmap_{host}_{port}_{timestamp}",
            evidence_source="nmap",
            evidence_type="port_scan",
            confidence="high" if version else "medium",
            timestamp=timestamp,
            raw_evidence={
                "port": port,
                "service": service,
                "version": version,
            }
        )
        self.links.append(link)
        return link
    
    def link_vulnerability_to_nuclei(
        self,
        vuln_name: str,
        host: str,
        matched_at: str,
        severity: str,
        timestamp: str,
    ) -> EvidenceLink:
        """
        Links a vulnerability to its nuclei evidence.
        """
        link = EvidenceLink(
            finding_id=f"vuln_{vuln_name}_{host}",
            finding_type="vulnerability",
            finding_host=host,
            evidence_id=f"nuclei_{host}_{timestamp}",
            evidence_source="nuclei",
            evidence_type="vulnerability_scan",
            confidence="high",
            timestamp=timestamp,
            raw_evidence={
                "matched_at": matched_at,
                "severity": severity,
            }
        )
        self.links.append(link)
        return link
    
    def get_links_for_host(self, host: str) -> List[EvidenceLink]:
        """
        Gets all evidence links for a specific host.
        """
        return [link for link in self.links if link.finding_host == host]
    
    def get_confidence_for_host(self, host: str) -> str:
        """
        Calculates overall confidence for a host based on evidence links.
        """
        links = self.get_links_for_host(host)
        if not links:
            return "low"
        
        high_count = sum(1 for l in links if l.confidence == "high")
        total = len(links)
        
        if high_count == total:
            return "high"
        elif high_count > 0:
            return "medium"
        return "low"
    
    def export_for_report(self) -> List[Dict[str, Any]]:
        """
        Exports evidence links in a format suitable for reporting.
        """
        return [
            {
                "finding": link.finding_id,
                "type": link.finding_type,
                "host": link.finding_host,
                "source": link.evidence_source,
                "evidence_type": link.evidence_type,
                "confidence": link.confidence,
                "timestamp": link.timestamp,
            }
            for link in self.links
        ]


# Global instance
evidence_linker = EvidenceLinker()


__all__ = ["EvidenceLinker", "EvidenceLink", "evidence_linker", "EvidenceLink"]