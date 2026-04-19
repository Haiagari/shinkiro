"""
Módulo de Inteligencia de OzyRecon
Maneja severidad, correlación, deduplicación y detección de novedades.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict

from src.core.logging import get_logger

logger = get_logger('intelligence')


# Pesos de CVSS para cálculo de severidad
CVSS_WEIGHTS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.0
}

# Mapeo de tipos de vulnerabilidad a severidad por defecto
VULN_TYPE_SEVERITY = {
    "rce": "critical",
    "command_injection": "critical",
    "sql_injection": "critical",
    "sqli": "critical",
    "deserialization": "critical",
    "broken_access_control": "high",
    "idor": "high",
    "auth_bypass": "high",
    "xss": "medium",
    "cross_site_scripting": "medium",
    "csrf": "low",
    "open_redirect": "low",
    "lfi": "high",
    "rfi": "critical",
    "ssrf": "high",
    "xxe": "high",
    "path_traversal": "medium",
    "info_disclosure": "low",
    "exposed_secret": "high",
    "exposed_panel": "low",
    "misconfiguration": "medium",
}


@dataclass
class SeverityResult:
    """Resultado del análisis de severidad."""
    severity: str
    cvss: Optional[float]
    confidence: float
    reasoning: str


class SeverityAnalyzer:
    """Analiza y asigna severidad a los hallazgos."""
    
    def __init__(self):
        self.custom_weights = {}
    
    def analyze(self, finding: Dict[str, Any]) -> SeverityResult:
        """
        Analiza un finding y determina su severidad.
        
        Args:
            finding: Diccionario con datos del finding
        
        Returns:
            SeverityResult con severidad asignada
        """
        # Si ya tiene severity y CVSS, usar esos
        if finding.get('severity'):
            return SeverityResult(
                severity=finding['severity'],
                cvss=finding.get('cvss'),
                confidence=1.0,
                reasoning=" severity provided"
            )
        
        # Determinar por tipo
        vuln_type = finding.get('type', '').lower()
        if vuln_type in VULN_TYPE_SEVERITY:
            severity = VULN_TYPE_SEVERITY[vuln_type]
            return SeverityResult(
                severity=severity,
                cvss=CVSS_WEIGHTS.get(severity),
                confidence=0.8,
                reasoning=f"Based on vulnerability type: {vuln_type}"
            )
        
        # Por defecto
        return SeverityResult(
            severity="medium",
            cvss=4.0,
            confidence=0.5,
            reasoning="Default severity"
        )
    
    def calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calcula un score de riesgo general."""
        total = 0.0
        for f in findings:
            result = self.analyze(f)
            total += result.cvss or 0
        
        # Normalizar a 0-100
        if not findings:
            return 0.0
        
        max_score = len(findings) * 10.0
        return min(100, (total / max_score) * 100)


class Deduplicator:
    """Deduplica hallazgos similares cruzando con la base de datos."""
    
    def __init__(self, db_session=None):
        self.db = db_session
    
    def fingerprint(self, finding: Dict[str, Any]) -> str:
        """Genera un hash único basado en la identidad del hallazgo."""
        import hashlib
        parts = [
            finding.get('type', ''),
            finding.get('host', ''),
            finding.get('path', ''),
            finding.get('param', ''),
            finding.get('name', '')
        ]
        raw = '|'.join(str(p).lower() for p in parts if p)
        return hashlib.md5(raw.encode()).hexdigest()
    
    def is_known(self, target: str, fingerprint: str) -> bool:
        """Verifica si el hallazgo ya existía en la DB para este target."""
        if not self.db: return False
        from src.storage.models import Finding
        return self.db.query(Finding).filter(
            Finding.target == target,
            Finding.evidence == fingerprint # Usamos evidence o una columna dedicada para el hash
        ).first() is not None

class NoveltyDetector:
    """Detecta novedades basándose en el historial de la DB."""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def analyze_novelty(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Clasifica hallazgos en NUEVOS o RECURRENTES."""
        from src.storage.models import Finding
        
        results = {'new': [], 'recurrent': []}
        
        # Obtener fingerprints conocidos de la DB
        known_findings = self.db.query(Finding.evidence).filter(Finding.target == target).all()
        known_hashes = {f[0] for f in known_findings}
        
        dedup = Deduplicator()
        for f in findings:
            f_hash = dedup.fingerprint(f)
            if f_hash in known_hashes:
                f['is_new'] = False
                results['recurrent'].append(f)
            else:
                f['is_new'] = True
                results['new'].append(f)
        
        return results

    
    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        """Fingerprint para detección de noveldad."""
        return f"{finding.get('type')}:{finding.get('host')}:{finding.get('path')}"
    
    def detect_novel(self, target: str, current: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detecta hallazgos nuevos respecto al anterior scan.
        
        Returns:
            Diccionario con: new, resolved, changed
        """
        previous = self.previous_findings.get(target, {})
        
        current_fps = {self._fingerprint(f): f for f in current}
        
        # Nuevos
        new_findings = []
        for fp, f in current_fps.items():
            if fp not in previous:
                f['status'] = 'new'
                new_findings.append(f)
        
        # Resueltos
        resolved = []
        for fp, f in previous.items():
            if fp not in current_fps:
                f['status'] = 'resolved'
                resolved.append(f)
        
        # Cambiados (misma ubicación, diferente descripción)
        changed = []
        # Por ahora vacío
        
        return {
            'new': new_findings,
            'resolved': resolved,
            'changed': changed,
            'total_new': len(new_findings),
            'total_resolved': len(resolved)
        }


# Instancias globales
severity_analyzer = SeverityAnalyzer()
deduplicator = Deduplicator()
correlation_engine = CorrelationEngine()
novelty_detector = NoveltyDetector()


def analyze_severity(finding: Dict[str, Any]) -> SeverityResult:
    """Función de conveniencia."""
    return severity_analyzer.analyze(finding)


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Función de conveniencia."""
    return deduplicator.deduplicate(findings)