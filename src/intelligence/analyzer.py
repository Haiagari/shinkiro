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
    """Deduplica hallazgos similares."""
    
    def __init__(self):
        self.fingerprint_cache = defaultdict(list)
    
    def fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Genera un fingerprint único para un finding.
        
        Usa: tipo + host + path + param
        """
        parts = [
            finding.get('type', ''),
            finding.get('host', ''),
            finding.get('url', ''),
            finding.get('path', ''),
            finding.get('param', '')
        ]
        return '|'.join(str(p) for p in parts if p)
    
    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Elimina hallazgos duplicados.
        
        Mantiene el primero encontrado y marca los demás.
        """
        seen = set()
        unique = []
        duplicates = []
        
        for f in findings:
            fp = self.fingerprint(f)
            
            if fp in seen:
                duplicates.append(f)
                # Incrementar contador si existe
                if 'seen_count' in f:
                    f['seen_count'] += 1
            else:
                seen.add(fp)
                f['is_duplicate'] = False
                unique.append(f)
        
        if duplicates:
            logger.info(f"Deduplicated {len(duplicates)} findings")
        
        return unique
    
    def group_by_type(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Agrupa hallazgos por tipo."""
        grouped = defaultdict(list)
        for f in findings:
            vtype = f.get('type', 'other')
            grouped[vtype].append(f)
        return dict(grouped)


class CorrelationEngine:
    """Encuentra correlaciones entre hallazgos."""
    
    def find_correlations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Encuentra hallazgos que pueden estar relacionados.
        
        Returns:
            Lista de correlaciones encontradas
        """
        correlations = []
        
        # Por ejemplo: XSS + CSRF en el mismo host
        hosts = defaultdict(list)
        for f in findings:
            host = f.get('host', f.get('url', ''))
            hosts[host].append(f)
        
        for host, host_findings in hosts.items():
            types = [f.get('type') for f in host_findings]
            
            # XSS + CSRF correlation
            if 'xss' in types and 'csrf' in types:
                correlations.append({
                    'type': 'xss_csrf_combo',
                    'host': host,
                    'severity': 'high',
                    'description': f'XSS and CSRF found on {host}',
                    'findings': [f for f in host_findings if f.get('type') in ['xss', 'csrf']]
                })
        
        return correlations


class NoveltyDetector:
    """Detecta hallazgos nuevos o cambios significativos."""
    
    def __init__(self):
        self.previous_findings = {}
    
    def set_previous(self, target: str, findings: List[Dict[str, Any]]):
        """Establece los hallazgos anteriores para comparación."""
        # Crear set de fingerprints previos
        self.previous_findings[target] = {
            self._fingerprint(f): f for f in findings
        }
    
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