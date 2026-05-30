"""
OzyRecon Mode Base - Definición de Contratos Operativos
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid
import re
from src.core.config import config
from src.core.contracts import MODE_ENVELOPE_FIELDS, validate_required_fields
from src.core.context import ScanContext, set_context
from src.scope.profiles import get_profile
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.storage.models import Session as ScanSession, WorkflowStep
from src.storage.diff import DiffEngine, DiffReport
from src.intelligence.novelty import novelty_alerter
from src.notifications.notifier import Notifier
from src.opsec.kill_switch import kill_switch
from src.export.normalizer import NormalizedExporter, ScanResult

from src.core.logging import get_logger

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

    def _sanitize_target(self, target: str) -> str:
        """Sanitizes the target input to prevent command injection."""
        if not target:
            return ""
        # Remove shell meta-characters
        sanitized = re.sub(r"[;&|`$<>^{}\[\]\s]", "", target)
        return sanitized

    def run(self) -> Dict[str, Any]:
        """Flujo de ejecución principal con manejo de ciclo de vida."""
        self.context.mark_running()
        self.context.record_event("mode", "execution started", mode=self.mode_name)
        self._upsert_session_summary(status="running")
        try:
            self.validate_preconditions()
            self.context.record_event("mode", "preconditions validated", mode=self.mode_name)
            self._ensure_runtime_scan()
            result = self.execute()
            
            # NOVELTY ANALYSIS v7 (Phase 3 & 9)
            try:
                diff = self.diff_engine.get_diff(self.target, self.runtime_scan.id)
                if diff.has_changes():
                    alerts = novelty_alerter.analyze_diff(diff)
                    self.context.record_event("novelty", "changes detected", summary=diff.summary(), count=len(alerts))
                    if isinstance(result, dict):
                        result["novelty"] = {
                            "summary": diff.summary(),
                            "events": alerts
                        }
            except Exception as e:
                self.context.record_event("novelty", "analysis failed", error=str(e))

            self.context.mark_completed()
            self.context.record_event("mode", "execution completed", mode=self.mode_name)
            if isinstance(result, dict) and "observability" not in result:
                result["observability"] = self.context.to_observability_record()
            
            self._persist_workflow_history()
            self._finalize_runtime_scan("completed")
            self._upsert_session_summary(status="success")
            return result
        except Exception as e:
            self.context.mark_failed(str(e))
            self.context.record_event("mode", "execution failed", mode=self.mode_name, error=str(e))
            self._persist_workflow_history()
            self._finalize_runtime_scan("failed", error_summary=str(e), exit_code=1)
            self._upsert_session_summary(status="failed", error_summary=str(e), exit_code=1)
            return self.build_output_envelope("failed", error=str(e))
        finally:
            # v7.7.2 - Garantía de Artefactos: Escribir a disco SIEMPRE
            try:
                from src.intelligence.orchestrator import DiscoveryOrchestrator
                # Solo si logramos tener un runtime_scan
                if self.runtime_scan:
                    orchestrator = DiscoveryOrchestrator(self.db_session, scan_id=self.runtime_scan.id)
                    orchestrator.finalize_session()
            except Exception as final_err:
                logger.error(f"Critical failure during artifact finalization: {final_err}")
            
            self.db_session.close()

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

        envelope = {
            "status": status,
            "session_id": self.session_id,
            "target": self.target,
            "mode": self.mode_name,
            "contract_version": result.contract_version,
            "result": result.to_dict(),
            "observability": self.context.to_observability_record(),
        }
        envelope.update(details)
        validate_required_fields(envelope, MODE_ENVELOPE_FIELDS)
        return envelope

    def _ensure_runtime_scan(self):
        """Crea o reutiliza el scan SQLAlchemy que representa esta ejecución."""
        if self.runtime_scan is not None:
            return self.runtime_scan

        existing = self.db.get_scan_by_session(self.session_id)
        if existing:
            self.runtime_scan = existing
            return self.runtime_scan

        self.runtime_scan = self.db.create_scan(
            self.target,
            self.session_id,
            mode=self.mode_name,
            status="running",
            start_time=self.context.started_at,
            subdomains_found=0,
            hosts_alive=0,
            ports_found=0,
            findings=0,
            out_dir=self.options.get("output"),
        )
        return self.runtime_scan

    def _finalize_runtime_scan(
        self,
        status: str,
        error_summary: Optional[str] = None,
        exit_code: int = 0,
    ):
        """Actualiza el scan persistido con el estado final de la ejecución."""
        if self.runtime_scan is None:
            return

        scan_status = "completed" if status in {"success", "completed"} else "failed"
        self.db.update_scan_status(
            self.runtime_scan.id,
            scan_status,
            subdomains_found=self.context.subdomains_found,
            hosts_alive=self.context.hosts_alive,
            ports_found=self.context.ports_found,
            findings=self.context.findings,
            errors=error_summary,
            out_dir=self.options.get("output"),
        )

    def _upsert_session_summary(
        self,
        status: str,
        error_summary: Optional[str] = None,
        exit_code: int = 0,
    ):
        """Persiste un resumen de sesión para reconstrucción de trazas."""
        session = self.db_session.query(ScanSession).filter(
            ScanSession.session_id == self.session_id
        ).first()

        counts = {
            "subdomains": self.context.subdomains_found,
            "hosts": self.context.hosts_alive,
            "ports": self.context.ports_found,
            "findings": self.context.findings,
        }

        if not session:
            session = ScanSession(
                session_id=self.session_id,
                target=self.target,
                mode=self.mode_name,
                started_at=self.context.started_at,
                status=status,
                exit_code=exit_code,
                config_used={
                    "threads": self.context.threads,
                    "rate_limit": self.context.rate_limit,
                    "mode": self.mode_name,
                },
                **counts,
            )
            self.db_session.add(session)
        else:
            session.target = self.target
            session.mode = self.mode_name
            session.status = status
            session.exit_code = exit_code
            session.subdomains = counts["subdomains"]
            session.hosts = counts["hosts"]
            session.ports = counts["ports"]
            session.findings = counts["findings"]
            session.config_used = {
                "threads": self.context.threads,
                "rate_limit": self.context.rate_limit,
                "mode": self.mode_name,
            }

        if status in {"success", "failed"}:
            session.ended_at = self.context.finished_at or datetime.now(timezone.utc)
            if self.context.duration is not None:
                session.duration = self.context.duration
            session.error_summary = error_summary

        self.db_session.commit()

    def _persist_workflow_history(self):
        """Vuelca la timeline del contexto en la base de datos."""
        import json
        target_obj = self.db.get_target(self.target)
        target_id = target_obj.id if target_obj else None

        for event in self.context.timeline:
            # Evitar duplicados simples si se llama varias veces (opcional)
            step = WorkflowStep(
                target_id=target_id,
                state=event.get("stage", "unknown").upper(),
                timestamp=datetime.fromisoformat(event["timestamp"]),
                actor="SYSTEM",
                notes=json.dumps({
                    "message": event.get("message"),
                    "data": event.get("data", {})
                })
            )
            self.db_session.add(step)
        
        try:
            self.db_session.commit()
        except Exception as e:
            logger.warning(f"Failed to persist workflow history: {e}")
