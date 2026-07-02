import tarfile
import json
import os
import shutil
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path
from src.domain.models import Finding, Evidence

class ArtifactStudio:
    """
    Generates professional reconnaissance artifacts ready for auditing.
    """

    def create_bundle(self, session_id: str, results: Dict[str, Any]) -> str:
        """
        Exports a signed JSON bundle containing findings, evidence, and metadata.
        Ready for OzyAudit.
        
        :param session_id: Unique identifier for the scan session.
        :param results: Dictionary containing 'findings' (List[Finding]) and 'evidence' (List[Evidence]).
        :return: JSON string of the bundle.
        """
        findings: List[Finding] = results.get("findings", [])
        evidence_list: List[Evidence] = results.get("evidence", [])

        bundle = {
            "version": "1.2",
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "total_evidence": len(evidence_list)
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "asset_id": f.asset_id,
                    "evidence_ids": f.evidence_ids,
                    "vulnerability_type": f.vulnerability_type,
                    "path": f.path,
                    "param": f.param
                } for f in findings
            ],
            "evidence": [
                {
                    "content_hash": e.content_hash,
                    "signature": e.signature,
                    "source": e.source,
                    "timestamp": e.timestamp.isoformat(),
                    "content": e.content,
                    "metadata": e.metadata
                } for e in evidence_list
            ],
            "metadata": {
                "generated_by": "PromptWall Conductor v1.2",
                "format": "OzyAudit-compatible"
            }
        }

        return json.dumps(bundle, indent=2)

    def create_audit_bundle(self, session_id: str, results: Any, output_dir: str) -> str:
        """
        Creates a professional directory structure for OzyAudit.
        
        Structure:
        - bundle/
            - findings.json
            - metadata.json
            - evidence/
                - [hash].json
        - [session_id].tar.gz
        """
        base_path = Path(output_dir) / f"audit_{session_id}"
        evidence_path = base_path / "evidence"
        
        # Cleanup and create structure
        if base_path.exists():
            shutil.rmtree(base_path)
        
        evidence_path.mkdir(parents=True)
        
        findings = results.get("findings", [])
        evidence_list = results.get("evidence", [])
        
        # 1. Save findings.json
        findings_data = [
            {
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "asset_id": f.asset_id,
                "evidence_ids": f.evidence_ids,
                "vulnerability_type": f.vulnerability_type,
                "path": f.path,
                "param": f.param
            } for f in findings
        ]
        with open(base_path / "findings.json", "w") as f:
            json.dump(findings_data, f, indent=2)
            
        # 2. Save evidence/
        for ev in evidence_list:
            ev_file = evidence_path / f"{ev.content_hash}.json"
            with open(ev_file, "w") as f:
                json.dump({
                    "content_hash": ev.content_hash,
                    "signature": ev.signature,
                    "source": ev.source,
                    "timestamp": ev.timestamp.isoformat(),
                    "content": ev.content,
                    "metadata": ev.metadata
                }, f, indent=2)
                
        # 3. Save metadata.json
        metadata = {
            "session_id": session_id,
            "generated_at": datetime.utcnow().isoformat(),
            "scan_info": results.get("scan_info", {}),
            "timing": results.get("timing", {}),
            "version": "1.2"
        }
        with open(base_path / "metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
            
        # 4. Compress into .tar.gz
        tar_path = Path(output_dir) / f"{session_id}.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(base_path, arcname=os.path.basename(base_path))
            
        return str(tar_path)
