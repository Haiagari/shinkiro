"""
Contexto de Ejecución de OzyRecon
Maneja el estado y metadata de cada ejecución.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class ScanContext:
    """Contexto de un escaneo específico."""
    
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    mode: str = "hunt"  # hunt, continuous, campaign, research, forensic, servicio
    
    # Timestamps
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    
    # Estado
    status: str = "pending"  # pending, running, completed, failed, interrupted
    progress: float = 0.0
    
    # Resultados preliminares
    subdomains_found: int = 0
    hosts_alive: int = 0
    ports_found: int = 0
    findings: int = 0
    
    # Flags de control
    opsec_enabled: bool = True
    dry_run: bool = False
    verbose: bool = False
    
    # Metadata adicional
    user_agent: str = ""
    rate_limit: int = 50
    threads: int = 10
    timeout_policy: Dict[str, int] = field(default_factory=dict)
    
    # Resultados (se填充an durante ejecución)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    def record_event(self, stage: str, message: str, **data: Any):
        """Agrega un evento a la línea de tiempo del scan."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "message": message,
        }
        if data:
            event["data"] = data
        self.timeline.append(event)
        return event
    
    def mark_running(self):
        """Marca el scan como en ejecución."""
        self.status = "running"
        self.record_event("status", "scan marked as running")
    
    def mark_completed(self):
        """Marca el scan como completado."""
        self.status = "completed"
        self.finished_at = datetime.now(timezone.utc)
        self.progress = 100.0
        self.record_event("status", "scan marked as completed", progress=self.progress)
    
    def mark_failed(self, error: str):
        """Marca el scan como fallido."""
        self.status = "failed"
        self.finished_at = datetime.now(timezone.utc)
        self.errors.append(error)
        self.record_event("status", "scan marked as failed", error=error)
    
    def mark_interrupted(self):
        """Marca el scan como interrumpido."""
        self.status = "interrupted"
        self.finished_at = datetime.now(timezone.utc)
        self.record_event("status", "scan marked as interrupted")
    
    def update_progress(self, step: str, progress: float):
        """Actualiza el progreso del scan."""
        self.progress = progress
        self.results[step] = {"status": "running", "progress": progress}
        self.record_event("progress", f"progress updated for {step}", step=step, progress=progress)
    
    def add_error(self, error: str):
        """Agrega un error al contexto."""
        self.errors.append(error)
        self.record_event("error", error)
    
    def add_result(self, key: str, value: Any):
        """Agrega un resultado."""
        self.results[key] = value
        self.record_event("result", f"result added for {key}", key=key)
    
    @property
    def duration(self) -> Optional[float]:
        """Duración del scan en segundos."""
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el contexto a diccionario."""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "progress": self.progress,
            "subdomains_found": self.subdomains_found,
            "hosts_alive": self.hosts_alive,
            "ports_found": self.ports_found,
            "findings": self.findings,
            "duration": self.duration,
            "results": self.results,
            "errors": self.errors,
            "timeline": self.timeline,
        }

    def to_observability_record(self) -> Dict[str, Any]:
        """
        Devuelve un record compacto para logs, trazas y depuración.
        Mantiene el contrato del contexto, pero añade derivados útiles.
        """
        base = self.to_dict()
        base["error_count"] = len(self.errors)
        base["result_keys"] = sorted(self.results.keys())
        base["event_count"] = len(self.timeline)
        base["last_event"] = self.timeline[-1] if self.timeline else None
        base["is_terminal"] = self.status in {"completed", "failed", "interrupted"}
        return base


@dataclass 
class TargetProfile:
    """Perfil de un target específico."""
    
    domain: str
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_scan: Optional[datetime] = None
    
    # Scope
    in_scope: bool = True
    scope_domains: List[str] = field(default_factory=list)
    
    # Tech stack detectado
    technologies: List[str] = field(default_factory=list)
    
    # Scoring
    priority_score: float = 0.0
    last_score: float = 0.0
    
    # Notas
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    
    def add_technology(self, tech: str):
        """Agrega una tecnología detectada."""
        if tech not in self.technologies:
            self.technologies.append(tech)
    
    def add_tag(self, tag: str):
        """Agrega un tag."""
        if tag not in self.tags:
            self.tags.append(tag)


# Contexto global
_current_context: Optional[ScanContext] = None


def get_context() -> ScanContext:
    """Obtiene el contexto actual o crea uno nuevo."""
    global _current_context
    if _current_context is None:
        _current_context = ScanContext()
    return _current_context


def set_context(ctx: ScanContext):
    """Establece el contexto actual."""
    global _current_context
    _current_context = ctx


def clear_context():
    """Limpia el contexto actual."""
    global _current_context
    _current_context = None
