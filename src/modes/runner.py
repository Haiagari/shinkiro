"""
ModeRunner - Orquestación del ciclo de vida de ejecución de modos.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

from src.core.logging import get_logger
from src.intelligence.pipeline.novelty import novelty_alerter

if TYPE_CHECKING:
    from src.modes.base import BaseMode

logger = get_logger("modes.runner")


class ModeRunner:
    """Executes the mode-specific logic with full lifecycle management."""

    def __init__(self, mode: BaseMode) -> None:
        self.mode = mode

    def run(self) -> Dict[str, Any]:
        """Flujo de ejecución principal con manejo de ciclo de vida."""
        mode = self.mode

        mode.context.mark_running()
        mode.context.record_event("mode", "execution started", mode=mode.mode_name)
        mode.session_manager.upsert_session_summary(
            mode.session_id, mode.target, mode.mode_name, mode.context,
            status="running",
        )

        try:
            mode.validate_preconditions()
            mode.context.record_event("mode", "preconditions validated", mode=mode.mode_name)

            mode.runtime_scan = mode.session_manager.ensure_runtime_scan(
                mode.target, mode.session_id, mode.mode_name,
                mode.context.started_at, mode.options,
            )
            result = mode.execute()

            # NOVELTY ANALYSIS v7 (Phase 3 & 9)
            try:
                diff = mode.diff_engine.get_diff(mode.target, mode.runtime_scan.id)
                if diff.has_changes():
                    alerts = novelty_alerter.analyze_diff(diff)
                    mode.context.record_event(
                        "novelty", "changes detected",
                        summary=diff.summary(), count=len(alerts),
                    )
                    if isinstance(result, dict):
                        result["novelty"] = {
                            "summary": diff.summary(),
                            "events": alerts,
                        }
            except Exception as e:
                mode.context.record_event("novelty", "analysis failed", error=str(e))

            mode.context.mark_completed()
            mode.context.record_event("mode", "execution completed", mode=mode.mode_name)

            if isinstance(result, dict) and "observability" not in result:
                result["observability"] = mode.context.to_observability_record()

            mode.session_manager.persist_workflow_history(mode.target, mode.context)
            mode.session_manager.finalize_runtime_scan(
                mode.runtime_scan, mode.context, mode.options, "completed",
            )
            mode.session_manager.upsert_session_summary(
                mode.session_id, mode.target, mode.mode_name, mode.context,
                status="success",
            )
            return result

        except Exception as e:
            mode.context.mark_failed(str(e))
            mode.context.record_event(
                "mode", "execution failed", mode=mode.mode_name, error=str(e),
            )
            mode.session_manager.persist_workflow_history(mode.target, mode.context)

            if mode.runtime_scan:
                mode.session_manager.finalize_runtime_scan(
                    mode.runtime_scan, mode.context, mode.options, "failed",
                    error_summary=str(e), exit_code=1,
                )
            mode.session_manager.upsert_session_summary(
                mode.session_id, mode.target, mode.mode_name, mode.context,
                status="failed", error_summary=str(e), exit_code=1,
            )
            return mode.build_output_envelope("failed", error=str(e))

        finally:
            # v7.7.2 - Garantía de Artefactos: Escribir a disco SIEMPRE
            try:
                from src.intelligence.pipeline.orchestrator import DiscoveryOrchestrator
                if mode.runtime_scan:
                    orchestrator = DiscoveryOrchestrator(
                        mode.db_session, scan_id=mode.runtime_scan.id,
                    )
                    orchestrator.finalize_session()
            except Exception as final_err:
                logger.error(
                    "Critical failure during artifact finalization: %s", final_err,
                )

            mode.db_session.close()
