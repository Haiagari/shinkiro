"""
Schema del Export Normalizado de OzyRecon
Define el formato estándar para interoperabilidad con OzyAudit.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum

from src.core.contracts import CONTRACT_VERSION


class SeverityLevel(str, Enum):
    """Niveles de severidad."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Tipos de hallazgos."""
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    EXPOSED_SECRET = "exposed_secret"
    EXPOSED_PANEL = "exposed_panel"
    OPEN_REDIRECT = "open_redirect"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIGURATION = "misconfiguration"
    CORS = "cors"
    CSRF = "csrf"
    OTHER = "other"


@dataclass
class Asset:
    """Un activo descubierto (subdominio, host, etc)."""
    type: str  # subdomain, ip, domain
    value: str
    is_live: bool = False
    ip: Optional[str] = None
    http_status: Optional[int] = None
    title: Optional[str] = None
    web_server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Service:
    """Un servicio detectado."""
    host: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class Evidence:
    """Evidencia de un finding."""
    type: str  # request, response, screenshot, log
    content: str
    timestamp: Optional[str] = None


@dataclass
class Finding:
    """Un hallazgo de vulnerabilidad."""
    name: str
    type: str  # FindingType
    severity: str  # SeverityLevel
    host: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    param: Optional[str] = None
    description: Optional[str] = None
    payload: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    cvss: Optional[float] = None
    cve_id: Optional[str] = None
    status: str = "open"  # open, confirmed, false_positive, duplicate, fixed


@dataclass
class Diff:
    """Resultado de la comparación entre dos escaneos."""
    type: str  # new, changed, removed
    category: str  # asset, service, finding
    old_value: Optional[str] = None
    new_value: Optional[str] = None


@dataclass
class ScanResult:
    """
    Schema principal del export normalizado.
    Este es el formato que OzyAudit espera para interpretar resultados.
    """
    # Metadata
    type: str = "scan-result"
    source: str = "ozy-recon"
    version: str = "1.0"
    contract_version: str = CONTRACT_VERSION
    
    # Identificación
    session_id: str = ""
    target: str = ""
    mode: str = "hunt"  # hunt, continuous, campaign, research, forensic, servicio
    
    # Tiempos
    timestamp: str = ""
    started_at: str = ""
    ended_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    # Resultados
    assets: List[Asset] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    diff: List[Diff] = field(default_factory=list)
    
    # Estadísticas
    stats: Dict[str, int] = field(default_factory=dict)
    
    # Config usada
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Errores
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convierte a JSON."""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_scan(cls, scan, db_queries=None) -> 'ScanResult':
        """Crea un ScanResult desde un objeto Scan de la base de datos."""
        result = cls(
            session_id=scan.session_id,
            target=scan.target.domain if scan.target else "",
            mode=scan.mode,
            timestamp=scan.timestamp,
            started_at=scan.start_time.isoformat() if scan.start_time else "",
            ended_at=scan.end_time.isoformat() if scan.end_time else None,
        )
        
        # Calcular duración
        if scan.start_time and scan.end_time:
            result.duration_seconds = (scan.end_time - scan.start_time).total_seconds()
        
        # Stats
        result.stats = {
            'subdomains_found': scan.subdomains_found,
            'hosts_alive': scan.hosts_alive,
            'ports_found': scan.ports_found,
            'findings': scan.findings,
        }

        if scan.errors:
            result.errors = [line.strip() for line in scan.errors.splitlines() if line.strip()]
        
        return result


# Ejemplo de uso:
"""
Ejemplo de output normalizado:

{
  "type": "scan-result",
  "source": "ozy-recon",
  "version": "1.0",
  "session_id": "abc123-def456",
  "target": "example.com",
  "mode": "hunt",
  "timestamp": "2026-04-19T12:00:00Z",
  "started_at": "2026-04-19T12:00:00Z",
  "ended_at": "2026-04-19T12:30:00Z",
  "duration_seconds": 1800.0,
  "assets": [
    {
      "type": "subdomain",
      "value": "api.example.com",
      "is_live": true,
      "ip": "0.0.0.0",
      "http_status": 200,
      "technologies": ["nginx", "python"]
    }
  ],
  "services": [
    {
      "host": "0.0.0.0",
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "version": "nginx/1.21",
      "state": "open"
    }
  ],
  "findings": [
    {
      "name": "SQL Injection",
      "type": "sqli",
      "severity": "critical",
      "url": "https://api.example.com/users",
      "param": "id",
      "description": "Boolean-based SQL injection",
      "cvss": 9.8
    }
  ],
  "diff": [],
  "stats": {
    "subdomains_found": 22,
    "hosts_alive": 8,
    "ports_found": 77,
    "findings": 2
  },
  "config": {
    "threads": 50,
    "rate_limit": 200
  },
  "errors": []
}
"""
