"""
Exportador Normalizado de OzyRecon
Genera outputs en formato estándar para OzyAudit.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from src.core.config import config
from src.core.logging import get_logger
from src.export.schema import (
    ScanResult, Asset, Service, Finding, Evidence, Diff,
    SeverityLevel, FindingType
)
from src.storage.queries import DBQueries

logger = get_logger('exporter')


class NormalizedExporter:
    """
    Exporta resultados en formato normalizado para OzyAudit.
    """
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.output_dir = Path(__file__).resolve().parents[2] / "runtime" / "exports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export_scan(
        self,
        session_id: str,
        target: str,
        mode: str = "hunt",
        include_assets: bool = True,
        include_services: bool = True,
        include_findings: bool = True,
        include_diff: bool = False,
        previous_session_id: Optional[str] = None
    ) -> ScanResult:
        """
        Exporta un scan en formato normalizado.
        
        Args:
            session_id: ID de la sesión a exportar
            target: Target escaneado
            mode: Modo de operación
            include_assets: Incluir assets descubiertos
            include_services: Incluir servicios detectados
            include_findings: Incluir vulnerabilidades
            include_diff: Incluir diferencias con scan anterior
            previous_session_id: Session ID anterior para diff
        
        Returns:
            ScanResult en formato normalizado
        """
        # Crear resultado base
        result = ScanResult(
            session_id=session_id,
            target=target,
            mode=mode,
            timestamp=datetime.now().isoformat(),
            started_at=datetime.now().isoformat(),
            config={
                'threads': config.threads,
                'timeout': config.timeout,
                'rate_limit': config.rate_limit,
            }
        )
        
        # Si tenemos sesión de DB, populate
        if self.db_session:
            db = DBQueries(self.db_session)
            scan = db.get_scan_by_session(session_id)
            
            if scan:
                result.started_at = scan.start_time.isoformat() if scan.start_time else ""
                result.ended_at = scan.end_time.isoformat() if scan.end_time else None
                
                if scan.start_time and scan.end_time:
                    result.duration_seconds = (scan.end_time - scan.start_time).total_seconds()

                if scan.errors:
                    result.errors = [line.strip() for line in scan.errors.splitlines() if line.strip()]
                
                # Stats
                result.stats = {
                    'subdomains_found': scan.subdomains_found,
                    'hosts_alive': scan.hosts_alive,
                    'ports_found': scan.ports_found,
                    'findings': scan.findings,
                }
                
                # Assets
                if include_assets:
                    for sub in scan.subdomains:
                        result.assets.append(self._asset_from_subdomain(sub))
                
                # Services
                if include_services:
                    for port in scan.ports:
                        result.services.append(self._service_from_port(port))
                
                # Findings
                if include_findings:
                    for vuln in scan.vulnerabilities:
                        result.findings.append(self._finding_from_vulnerability(vuln))
                
                # Diff
                if include_diff and previous_session_id:
                    previous_scan = db.get_scan_by_session(previous_session_id)
                    if previous_scan:
                        diffs = self._compute_diff(scan, previous_scan)
                        result.diff = diffs
        
        return result

    def _asset_from_subdomain(self, subdomain) -> Asset:
        metadata = {
            "asn": subdomain.asn,
            "asn_organization": subdomain.asn_organization,
            "cloud_provider": subdomain.cloud_provider,
            "env_tag": subdomain.env_tag,
            "semantic_labels": subdomain.semantic_labels,
            "business_impact": subdomain.business_impact
        }
        return Asset(
            type="subdomain",
            value=subdomain.domain,
            is_live=bool(subdomain.is_live),
            ip=subdomain.ip,
            http_status=subdomain.http_status,
            title=subdomain.title,
            web_server=subdomain.web_server,
            technologies=subdomain.technologies or [],
            metadata=metadata
        )

    def _service_from_port(self, port) -> Service:
        return Service(
            host=port.host,
            port=port.port,
            protocol=port.protocol,
            service=port.service or "",
            version=port.version or "",
            state=port.state,
        )

    def _finding_from_vulnerability(self, vuln) -> Finding:
        evidence_items = []
        if vuln.evidence:
            evidence_items.append(Evidence(type="log", content=vuln.evidence))
        if vuln.payload:
            evidence_items.append(Evidence(type="request", content=vuln.payload))

        return Finding(
            name=vuln.name,
            type=vuln.type or "other",
            severity=vuln.severity or "info",
            host=vuln.host,
            url=vuln.path or vuln.host or "",
            path=vuln.path,
            param=vuln.param,
            description=vuln.description,
            payload=vuln.payload,
            evidence=evidence_items,
            cvss=vuln.cvss,
            status=vuln.status,
        )

    def _compute_diff(self, current_scan, previous_scan) -> List[Diff]:
        """Calcula diferencias entre dos scans."""
        diffs = []
        
        # Obtener subdominios previos
        prev_subdomains = {s.domain: s for s in previous_scan.subdomains}
        curr_subdomains = {s.domain: s for s in current_scan.subdomains}
        
        # Nuevos subdominios
        for domain in curr_subdomains:
            if domain not in prev_subdomains:
                diffs.append(Diff(
                    type="new",
                    category="asset",
                    new_value=domain
                ))
        
        # Subdominios removidos
        for domain in prev_subdomains:
            if domain not in curr_subdomains:
                diffs.append(Diff(
                    type="removed",
                    category="asset",
                    old_value=domain
                ))
        
        # Puertos
        prev_ports = {(p.host, p.port) for p in previous_scan.ports}
        curr_ports = {(p.host, p.port) for p in current_scan.ports}
        
        for port in curr_ports - prev_ports:
            diffs.append(Diff(
                type="new",
                category="service",
                new_value=f"{port[0]}:{port[1]}"
            ))
        
        for port in prev_ports - curr_ports:
            diffs.append(Diff(
                type="removed",
                category="service",
                old_value=f"{port[0]}:{port[1]}"
            ))

        prev_findings = {self._finding_key(v): v for v in previous_scan.vulnerabilities}
        curr_findings = {self._finding_key(v): v for v in current_scan.vulnerabilities}

        for key, vuln in curr_findings.items():
            if key not in prev_findings:
                diffs.append(Diff(
                    type="new",
                    category="finding",
                    new_value=self._finding_value(vuln)
                ))
            else:
                prev_vuln = prev_findings[key]
                if (
                    (prev_vuln.severity or "info") != (vuln.severity or "info")
                    or (prev_vuln.status or "open") != (vuln.status or "open")
                    or (prev_vuln.cvss or 0) != (vuln.cvss or 0)
                ):
                    diffs.append(Diff(
                        type="changed",
                        category="finding",
                        old_value=self._finding_value(prev_vuln),
                        new_value=self._finding_value(vuln),
                    ))

        for key, vuln in prev_findings.items():
            if key not in curr_findings:
                diffs.append(Diff(
                    type="removed",
                    category="finding",
                    old_value=self._finding_value(vuln)
                ))
        
        return diffs

    @staticmethod
    def _finding_key(vuln) -> str:
        return "|".join([
            vuln.name or "",
            vuln.type or "",
            vuln.host or "",
            vuln.path or "",
            vuln.param or "",
        ])

    @staticmethod
    def _finding_value(vuln) -> str:
        location = vuln.path or vuln.host or ""
        return f"{vuln.name}::{location}"

    def save_json(self, result: ScanResult, filename: Optional[str] = None) -> Path:
        """Guarda el resultado en un archivo JSON."""
        if not filename:
            filename = f"scan_{result.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.output_dir / result.target / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(result.to_json())
        
        logger.info(f"Exported to {filepath}")
        return filepath
    
    def save_markdown(self, result: ScanResult, filename: Optional[str] = None) -> Path:
        """Guarda el resultado en formato Markdown legible."""
        if not filename:
            filename = f"summary_{result.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        filepath = self.output_dir / result.target / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        md_content = self._generate_markdown(result)
        
        with open(filepath, 'w') as f:
            f.write(md_content)
        
        logger.info(f"Exported markdown to {filepath}")
        return filepath
    
    def _generate_markdown(self, result: ScanResult) -> str:
        """Genera un resumen en Markdown."""
        md = []
        md.append(f"# OzyRecon Scan Report")
        md.append(f"")
        md.append(f"**Target:** {result.target}")
        md.append(f"**Mode:** {result.mode}")
        md.append(f"**Session:** {result.session_id}")
        md.append(f"**Timestamp:** {result.timestamp}")
        md.append(f"")
        
        # Stats
        md.append(f"## Statistics")
        md.append(f"")
        md.append(f"| Metric | Value |")
        md.append(f"|--------|-------|")
        md.append(f"| Subdomains | {result.stats.get('subdomains_found', 0)} |")
        md.append(f"| Hosts Alive | {result.stats.get('hosts_alive', 0)} |")
        md.append(f"| Ports Found | {result.stats.get('ports_found', 0)} |")
        md.append(f"| Findings | {result.stats.get('findings', 0)} |")
        md.append(f"")
        
        # Assets
        if result.assets:
            md.append(f"## Assets Discovered")
            md.append(f"")
            for asset in result.assets[:20]:  # Limit to 20
                md.append(f"- **{asset.value}** (live: {asset.is_live})")
                if asset.technologies:
                    md.append(f"  - Tech: {', '.join(asset.technologies)}")
            md.append(f"")
        
        # Findings
        if result.findings:
            md.append(f"## Findings")
            md.append(f"")
            for finding in result.findings:
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢',
                    'info': '🔵'
                }.get(finding.severity, '⚪')
                
                md.append(f"{severity_icon} **{finding.name}** ({finding.severity.upper()})")
                if finding.url:
                    md.append(f"  - URL: {finding.url}")
                if finding.description:
                    md.append(f"  - {finding.description[:200]}")
                md.append(f"")
        
        # Diff
        if result.diff:
            md.append(f"## Changes from Previous Scan")
            md.append(f"")
            for d in result.diff:
                icon = "➕" if d.type == "new" else "➖" if d.type == "removed" else "🔄"
                md.append(f"{icon} {d.category}: {d.new_value or d.old_value}")
            md.append(f"")
        
        return "\n".join(md)

    def save_learning_report(self) -> Path:
        """Genera un reporte del estado de aprendizaje del sistema."""
        from src.intelligence.learning_orchestrator import learning_orchestrator
        
        data = learning_orchestrator.get_full_feedback()
        filename = f"learning_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / "intelligence" / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Learning report saved to {filepath}")
        return filepath


# Instancia global
exporter = NormalizedExporter()


def export_session(
    session_id: str,
    target: str,
    mode: str = "hunt",
    db_session=None,
    format: str = "json"
) -> Path:
    """
    Función utilitaria para exportar una sesión.
    
    Args:
        session_id: ID de la sesión
        target: Target
        mode: Modo de operación
        db_session: Sesión de DB
        format: 'json', 'markdown', o 'both'
    
    Returns:
        Path al archivo exportado
    """
    exp = NormalizedExporter(db_session)
    result = exp.export_scan(session_id, target, mode)
    
    if format == "json":
        return exp.save_json(result)
    elif format == "markdown":
        return exp.save_markdown(result)
    else:  # both
        json_path = exp.save_json(result)
        md_path = exp.save_markdown(result)
        return json_path
