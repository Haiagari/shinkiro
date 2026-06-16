"""
SIEM Exporter (OzyRecon v7.5 - Enterprise Layer)
Exports discovery findings and intelligence in structured formats (CEF/JSON).
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class SIEMExporter:
    """
    Handles structured data export for Enterprise integration.
    Supports JSON and basic CEF (Common Event Format).
    """

    def __init__(self, export_dir: str = "exports/siem"):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def export_as_json(self, data: List[Dict], filename: str = None) -> str:
        """Exports data as a flat JSON file for ELK/Splunk ingest."""
        if not filename:
            filename = f"ozy_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        path = self.export_dir / filename
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Exported {len(data)} items to {path} (JSON)")
            return str(path)
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            return ""

    def export_to_cef(self, finding: Dict) -> str:
        """
        Converts a finding to Common Event Format (CEF).
        CEF:Timestamp|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
        """
        vendor = "Antigravity"
        product = "OzyRecon"
        version = "7.5.0"
        sig_id = finding.get("type", "discovery")
        name = finding.get("domain") or finding.get("host") or "finding"
        severity = self._map_severity_to_cef(finding.get("business_impact") or finding.get("severity"))
        
        # Extensions
        # Mapeo flexible para v7.5 y DB fields
        labels = finding.get('semantic_labels') or finding.get('labels', [])
        impact = finding.get('business_impact') or finding.get('impact', 'INFO')
        
        ext = f"labels={labels} impact={impact} "
        if finding.get("ip"): ext += f"src={finding.get('ip')} "
        if finding.get("evidence_signature"): ext += f"sig={finding.get('evidence_signature')[:16]}..."

        cef = f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{severity}|{ext}"
        return cef

    def _map_severity_to_cef(self, sev: str) -> int:
        mapping = {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
            "INFO": 1
        }
        return mapping.get(str(sev).upper(), 0)

    def generate_forensic_bundle(self, session_id: str, findings: List[Dict], public_key: str) -> str:
        """
        Generates a standalone signed JSON bundle for external auditors (v8.3.2).
        Includes the public key for self-contained verification.
        """
        bundle = {
            "version": "1.0",
            "type": "ozy_forensic_bundle",
            "session_id": session_id,
            "exported_at": datetime.now().isoformat(),
            "public_key": public_key,
            "findings": findings
        }
        
        filename = f"forensic_bundle_{session_id}.json"
        path = self.export_dir / filename
        with open(path, "w") as f:
            json.dump(bundle, f, indent=2, default=str)
        
        logger.info(f"Forensic bundle generated: {path}")
        return str(path)

# Global Instance
siem_exporter = SIEMExporter()
