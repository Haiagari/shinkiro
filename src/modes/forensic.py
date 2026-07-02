"""
Forensic Mode - PromptWall v7.7
Reconstructs and verifies evidence signatures for a past session.
"""

import logging
from typing import Dict, Any, List
from src.modes.base import BaseMode
from src.utils.crypto import evidence_signer
from src.storage.models import Subdomain
from src.core.logging import console
from rich.table import Table

logger = logging.getLogger('mode.forensic')

class ForensicMode(BaseMode):
    def __init__(self, session_id: str, options: Dict[str, Any] = None):
        # In forensic mode, target is derived from session_id
        super().__init__("forensic_audit", "forensic", options)
        self.audit_session_id = session_id

    def validate_preconditions(self):
        if not self.audit_session_id:
            raise ValueError("Session ID is required for FORENSIC mode")

    def execute(self) -> Dict[str, Any]:
        console.print(f"[bold cyan]🔍 Starting Forensic Audit for Session: {self.audit_session_id}[/bold cyan]")
        
        # 1. Fetch assets for the session
        assets = self.db_session.query(Subdomain).filter_by(scan_id=self._get_scan_id_from_session()).all()
        
        if not assets:
            return {"status": "failed", "error": "No assets found for this session"}

        table = Table(title=f"Forensic Integrity Audit: {self.audit_session_id}")
        table.add_column("Asset", style="cyan")
        table.add_column("Signature", style="dim")
        table.add_column("Status", justify="center")

        verified_count = 0
        failed_count = 0

        for asset in assets:
            if not asset.evidence_signature:
                table.add_row(asset.domain, "N/A", "[yellow]NO SIGNATURE[/yellow]")
                continue

            # Re-construct data object for verification
            # This must match the exact dictionary structure used during signing in orchestrator.py
            data_to_verify = {
                "domain": asset.domain,
                "ip": asset.ip,
                "http_status": asset.http_status,
                "title": asset.title,
                "semantic_labels": asset.semantic_labels
            }
            
            is_valid = evidence_signer.verify_data(data_to_verify, asset.evidence_signature)
            
            if is_valid:
                status = "[green]✅ VERIFIED[/green]"
                verified_count += 1
            else:
                status = "[red]❌ COMPROMISED[/red]"
                failed_count += 1
                
            table.add_row(asset.domain, f"{asset.evidence_signature[:16]}...", status)

        console.print(table)
        
        summary = f"Audit complete. Verified: {verified_count}, Failed: {failed_count}"
        if failed_count > 0:
            console.print(f"[bold red]⚠️ ALERT: {failed_count} evidence items failed integrity check![/bold red]")
        else:
            console.print("[bold green]✅ Integrity Audit PASSED. All evidence is authentic.[/bold green]")

        return {
            "status": "completed",
            "verified": verified_count,
            "failed": failed_count,
            "summary": summary
        }

    def _get_scan_id_from_session(self) -> int:
        from src.storage.models import Scan
        scan = self.db_session.query(Scan).filter_by(session_id=self.audit_session_id).first()
        return scan.id if scan else 0

def run_forensic(session_id: str, **options) -> Dict[str, Any]:
    return ForensicMode(session_id, options).run()
