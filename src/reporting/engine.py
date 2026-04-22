"""
Report Engine - Generación de reportes estructurados v5.0
"""

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
from src.storage.database import SessionLocal
from src.storage.models import Hypothesis, Evidence, WorkflowStep, Target
from src.core.logging import get_logger

logger = get_logger('reporting')

class ReportEngine:
    def __init__(self, out_dir: Path = None):
        self.out_dir = out_dir or Path("runtime/exports")

    def generate_markdown_finding(self, hypothesis_id: str) -> str:
        """
        Genera un bloque Markdown detallado para un hallazgo validado.
        """
        db = SessionLocal()
        try:
            hypo = db.query(Hypothesis).filter(Hypothesis.id == hypothesis_id).first()
            if not hypo:
                return "Hypothesis not found"

            evidences = db.query(Evidence).filter(Evidence.hypothesis_id == hypothesis_id).all()
            
            md = []
            md.append(f"## Finding: {hypo.type.upper()}")
            md.append(f"- **Status**: {hypo.status.upper()}")
            md.append(f"- **Severity**: {hypo.severity}")
            md.append(f"- **Confidence**: {hypo.confidence * 100:.0f}%")
            md.append(f"- **Target**: {hypo.url or 'N/A'}")
            
            md.append("\n### 🧠 Hypothesis")
            md.append(hypo.description)
            
            md.append("\n### 🔬 Validation Details")
            md.append(f"Validation Method: {hypo.validation_method or 'Standard controlled probe'}")
            
            if evidences:
                md.append("\n### 📂 Evidence Collected")
                for ev in evidences:
                    md.append(f"#### Evidence ID: `{ev.id}`")
                    md.append(f"- **Type**: {ev.type}")
                    md.append(f"- **Timestamp**: {ev.timestamp.isoformat()}")
                    md.append(f"- **Data**: `{ev.data}`")
                    if ev.metadata_json:
                        md.append(f"- **Metadata**: ```json\n{ev.metadata_json}\n```")
                    md.append(f"- **Integrity Hash (SHA256)**: `{ev.hash_sha256}`")
            
            return "\n".join(md)
        finally:
            db.close()

    def generate_full_report(self, session_id: str, target: str) -> Path:
        """
        Genera un reporte completo de la sesión.
        """
        db = SessionLocal()
        try:
            # Obtenemos todas las hipótesis validadas de la sesión
            # Nota: Necesitamos filtrar por session_id si lo agregamos a Hypothesis
            # Por ahora usamos el target
            hypos = db.query(Hypothesis).filter(
                Hypothesis.status == "validated"
            ).all()

            report_path = self.out_dir / target / f"v5_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)

            md = []
            md.append(f"# OzyRecon v5.0 Offensive Validation Report")
            md.append(f"- **Target**: {target}")
            md.append(f"- **Date**: {datetime.now().isoformat()}")
            md.append("\n---")
            
            for h in hypos:
                md.append(self.generate_markdown_finding(h.id))
                md.append("\n---\n")

            report_path.write_text("\n".join(md))
            logger.info(f"Full v5 report generated at {report_path}")
            return report_path
        finally:
            db.close()

# Instancia global
report_engine = ReportEngine()
