"""
Exportadores específicos para plataformas de Bug Bounty
Convierte los resultados al formato de cada plataforma.
"""

import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path

from src.export.schema import ScanResult, Finding
from src.core.logging import get_logger

logger = get_logger('platform_exporter')


class PlatformExporter(ABC):
    """Clase base para exportadores de plataformas."""
    
    @abstractmethod
    def export(self, result: ScanResult, output_path: Path) -> Path:
        """Exporta los resultados al formato de la plataforma."""
        pass


class HackerOneExporter(PlatformExporter):
    """Exportador para HackerOne."""
    
    def export(self, result: ScanResult, output_path: Path) -> Path:
        """Exporta en formato compatible con H1."""
        # H1 espera un formato específico
        report = {
            "title": "",
            "vulnerability": {
                "type": "",
                "severity": "",
                "description": "",
                "cve": None,
                "cwe": None,
                "cvss": None,
            },
            "impact": "",
            "steps_to_reproduce": [],
            "remediation": "",
            "references": [],
        }
        
        # Si hay hallazgos, usar el primero
        if result.findings:
            finding = result.findings[0]
            report["title"] = f"[{finding.severity.upper()}] {finding.name} in {finding.url or finding.host}"
            report["vulnerability"]["type"] = finding.type
            report["vulnerability"]["severity"] = finding.severity
            report["vulnerability"]["description"] = finding.description or ""
            report["vulnerability"]["cvss"] = finding.cvss
            report["impact"] = finding.description or ""
            report["steps_to_reproduce"] = [
                f"1. Navigate to {finding.url or finding.host}",
                f"2. {finding.payload or 'N/A'}"
            ]
        
        output_path = output_path / f"h1_{result.session_id}.json"
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Exported to H1 format: {output_path}")
        return output_path


class BugcrowdExporter(PlatformExporter):
    """Exportador para Bugcrowd."""
    
    def export(self, result: ScanResult, output_path: Path) -> Path:
        """Exporta en formato compatible con Bugcrowd."""
        report = {
            "title": "",
            "category": "",
            "severity": "",
            "description": "",
            "steps_to_reproduce": "",
            "url": "",
            "evidence": "",
        }
        
        if result.findings:
            finding = result.findings[0]
            report["title"] = f"{finding.name}"
            report["category"] = finding.type
            report["severity"] = self._map_severity(finding.severity)
            report["description"] = finding.description or ""
            report["url"] = finding.url or ""
            report["evidence"] = finding.payload or ""
            report["steps_to_reproduce"] = f"Target: {result.target}\nPayload: {finding.payload or 'N/A'}"
        
        output_path = output_path / f"bugcrowd_{result.session_id}.json"
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Exported to Bugcrowd format: {output_path}")
        return output_path
    
    def _map_severity(self, severity: str) -> str:
        """Mapea severidad al formato de Bugcrowd."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "informational"
        }
        return mapping.get(severity, "low")


class ImmunefiExporter(PlatformExporter):
    """Exportador para Immunefi."""
    
    def export(self, result: ScanResult, output_path: Path) -> Path:
        """Exporta en formato compatible con Immunefi."""
        report = {
            "title": "",
            "type": "",
            "severity": "",
            "description": "",
            "target": result.target,
            "impact": "",
            "reproduction_steps": [],
            "fix_recommendation": "",
        }
        
        if result.findings:
            finding = result.findings[0]
            report["title"] = f"{finding.name} on {result.target}"
            report["type"] = finding.type
            report["severity"] = self._map_severity(finding.severity)
            report["description"] = finding.description or ""
            report["impact"] = finding.description or ""
            report["reproduction_steps"] = [f"1. Target: {finding.url or result.target}"]
        
        output_path = output_path / f"immunefi_{result.session_id}.json"
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Exported to Immunefi format: {output_path}")
        return output_path
    
    def _map_severity(self, severity: str) -> str:
        """Mapea severidad al formato de Immunefi."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        return mapping.get(severity, "low")


# Registry de exportadores
EXPORTERS = {
    'hackerone': HackerOneExporter(),
    'bugcrowd': BugcrowdExporter(),
    'immunefi': ImmunefiExporter(),
}


def export_to_platform(
    result: ScanResult,
    platform: str,
    output_dir: Path
) -> Path:
    """
    Exporta resultados a una plataforma específica.
    
    Args:
        result: ScanResult normalizado
        platform: 'hackerone', 'bugcrowd', o 'immunefi'
        output_dir: Directorio de salida
    
    Returns:
        Path al archivo exportado
    """
    exporter = EXPORTERS.get(platform.lower())
    
    if not exporter:
        raise ValueError(f"Unknown platform: {platform}. Available: {list(EXPORTERS.keys())}")
    
    return exporter.export(result, output_dir)