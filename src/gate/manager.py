"""
Human Gate Manager - Control de decisiones críticas v5.0
"""

from typing import List, Dict, Any
from src.workflow.engine import workflow_engine
from src.workflow.states import WorkflowState, Actor
from src.core.logging import get_logger
from src.storage.database import SessionLocal
from src.storage.models import Hypothesis

logger = get_logger('human_gate')

class GateManager:
    def __init__(self):
        pass

    def list_pending(self) -> List[Dict[str, Any]]:
        """Lista las hipótesis esperando aprobación."""
        db = SessionLocal()
        try:
            pending = db.query(Hypothesis).filter(Hypothesis.status == WorkflowState.PENDING_APPROVAL).all()
            return [
                {
                    "id": h.id,
                    "target": h.target_id,
                    "type": h.type,
                    "description": h.description,
                    "confidence": h.confidence,
                    "risk": h.risk_level,
                    "signals": h.signals
                } for h in pending
            ]
        finally:
            db.close()

    def approve(self, hypothesis_id: str, notes: str = None):
        """Aprueba una hipótesis para validación."""
        return workflow_engine.transition_hypothesis(
            hypothesis_id, 
            WorkflowState.APPROVED, 
            actor=Actor.USER, 
            notes=notes or "Approved by operator"
        )

    def reject(self, hypothesis_id: str, reason: str = None):
        """Rechaza una hipótesis."""
        return workflow_engine.transition_hypothesis(
            hypothesis_id, 
            WorkflowState.REJECTED, 
            actor=Actor.USER, 
            notes=reason or "Rejected by operator"
        )

    def request_more_data(self, hypothesis_id: str, detail: str):
        """Mueve a un estado intermedio para recolectar más señales (opcional v5.1)."""
        return workflow_engine.transition_hypothesis(
            hypothesis_id, 
            WorkflowState.ANALYZED, 
            actor=Actor.USER, 
            notes=f"More data requested: {detail}"
        )

# Instancia global
gate_manager = GateManager()
