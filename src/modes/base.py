"""
OzyRecon Mode Base - Definición de Contratos Operativos
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import re
from src.core.config import config
from src.core.contracts import MODE_ENVELOPE_FIELDS, validate_required_fields
from src.core.context import ScanContext, set_context
from src.scope.profiles import get_profile
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.storage.diff import DiffEngine, DiffReport
from src.notifications.notifier import Notifier
from src.opsec.kill_switch import kill_switch
from src.export.normalizer import NormalizedExporter, ScanResult

from src.core.logging import get_logger
from src.modes.runner import ModeRunner
from src.modes.session import SessionManager
from src.modes.envelope import EnvelopeBuilder

logger = get_logger('modes.base')

class BaseMode(ABC):
    """
    Contrato base para todos los modos operativos de OzyRecon.
    Define precondiciones, flujo de ejecución y estructura de salida.
    """
    
    def __init__(self, target: str, mode_name: str, options: Optional[Dict[str, Any]] = None):
        self.target = self._sanitize_target(target)
        self.mode_name = mode_name
        self.options = options or {}
        
        # v7.7.2 - Support session_id override from API to ensure deterministic IDs
        self.session_id = self.options.get("session_id_override") or str(uuid.uuid4())
        self.runtime_scan = None
        
        # Contexto de ejecución
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode=mode_name,
            threads=self.options.get('threads', config.threads)
        )
        profile = get_profile(self.options.get("scan_profile", "safe-active"))
        if profile:
            self.context.timeout_policy = dict(profile.timeout_policy)
        set_context(self.context)
        self.context.record_event("mode", "mode initialized", mode=mode_name, target=target)
        
        # Componentes base
        init_db()
        self.db_session = SessionLocal()
        self.db = DBQueries(self.db_session)
        self.diff_engine = DiffEngine(self.db_session)
        self.notifier = Notifier()

        # v10 - Componentes extraídos
        self.session_manager = SessionManager(self.db_session)
        self.envelope_builder = EnvelopeBuilder()
        self.mode_runner = ModeRunner(self)

    def _sanitize_target(self, target: str) -> str:
        """Sanitizes the target input to prevent command injection."""
        if not target:
            return ""
        # Remove shell meta-characters
        sanitized = re.sub(r"[;&|`$<>^{}\[\]\s]", "", target)
        return sanitized

    def run(self) -> Dict[str, Any]:
        """Flujo de ejecución principal delegado a ModeRunner."""
        return self.mode_runner.run()

    @abstractmethod
    def validate_preconditions(self):
        """Verifica si el entorno y los datos previos permiten ejecutar este modo."""
        pass

    @abstractmethod
    def execute(self) -> Dict[str, Any]:
        """Lógica específica del modo."""
        pass

    def get_operational_intent(self) -> Dict[str, Any]:
        """
        Retorna la intención operativa para pasar a los proveedores.
        Define agresividad, ruido y velocidad.
        """
        return {
            "mode": self.mode_name,
            "speed": self.options.get("speed", "normal"),
            "noise_level": self.options.get("noise", "medium"),
            "depth": self.options.get("depth", "standard")
        }

    def build_normalized_result(self, include_diff: bool = False, previous_session_id: Optional[str] = None) -> ScanResult:
        """
        Construye el contrato normalizado de salida para el modo actual.
        Si existe un scan persistido, lo exporta; si no, devuelve un skeleton estable.
        """
        exporter = NormalizedExporter(self.db_session)
        scan = self.db.get_scan_by_session(self.session_id)

        if scan:
            return exporter.export_scan(
                self.session_id,
                self.target,
                mode=self.mode_name,
                include_diff=include_diff,
                previous_session_id=previous_session_id
            )

        result = ScanResult(
            session_id=self.session_id,
            target=self.target,
            mode=self.mode_name,
            timestamp=datetime.now().isoformat(),
            started_at=self.context.started_at.isoformat(),
            config={
                "threads": self.context.threads,
                "rate_limit": self.context.rate_limit,
                "noise": self.get_operational_intent().get("noise_level"),
                "depth": self.get_operational_intent().get("depth"),
            },
            errors=list(self.context.errors),
        )
        result.stats = {
            "subdomains_found": self.context.subdomains_found,
            "hosts_alive": self.context.hosts_alive,
            "ports_found": self.context.ports_found,
            "findings": self.context.findings,
        }
        return result

    def build_output_envelope(self, status: str, **details) -> Dict[str, Any]:
        """
        Devuelve un sobre de salida estable para todos los modos.
        """
        include_diff = bool(details.pop("include_diff", False))
        previous_session_id = details.pop("previous_session_id", None)
        result = self.build_normalized_result(
            include_diff=include_diff,
            previous_session_id=previous_session_id
        )
        return EnvelopeBuilder.build(
            status=status,
            session_id=self.session_id,
            target=self.target,
            mode=self.mode_name,
            contract_version=result.contract_version,
            result=result.to_dict(),
            observability=self.context.to_observability_record(),
            **details,
        )

    def _ensure_runtime_scan(self):
        """Crea o reutiliza el scan. Delega en SessionManager."""
        self.runtime_scan = self.session_manager.ensure_runtime_scan(
            self.target, self.session_id, self.mode_name,
            self.context.started_at, self.options,
        )
        return self.runtime_scan

    def _finalize_runtime_scan(
        self,
        status: str,
        error_summary: Optional[str] = None,
        exit_code: int = 0,
    ):
        """Actualiza el scan persistido. Delega en SessionManager."""
        self.session_manager.finalize_runtime_scan(
            self.runtime_scan, self.context, self.options,
            status, error_summary=error_summary, exit_code=exit_code,
        )

    def _persist_workflow_history(self):
        """Vuelca la timeline del contexto. Delega en SessionManager."""
        self.session_manager.persist_workflow_history(self.target, self.context)
