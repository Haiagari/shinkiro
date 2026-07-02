"""Professional report generation for PromptWall security assessments."""

from src.reporting.report import ProfessionalReport, Evidence
from src.reporting.cvss import CVSSVector, severity_from_score, score_finding, FINDING_TEMPLATES
from src.reporting.pdf_export import generate_pdf
from src.reporting.evidence import EvidenceCollector
from src.reporting.screenshots import capture_screenshot, capture_batch
from src.reporting.cve_lookup import CVEChecker, CVEEntry

__all__ = [
    "ProfessionalReport",
    "Evidence",
    "CVSSVector",
    "severity_from_score",
    "score_finding",
    "FINDING_TEMPLATES",
    "generate_pdf",
    "EvidenceCollector",
    "capture_screenshot",
    "capture_batch",
    "CVEChecker",
    "CVEEntry",
]
