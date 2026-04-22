"""
Workflow Engine - Gestión de estados y trazabilidad v5.0
"""

from datetime import datetime
from typing import Optional, List
from src.storage.database import SessionLocal
from src.storage.models import Hypothesis, WorkflowStep, Target
from src.workflow.states import WorkflowState, Actor
from src.core.logging import get_logger

logger = get_logger('workflow_engine')

class WorkflowEngine:
    def __init__(self):
        self.db = SessionLocal()

    def transition_hypothesis(self, hypothesis_id: str, new_state: str, actor: str = Actor.SYSTEM, notes: str = None):
        """
        Cambia el estado de una hipótesis y registra el paso en el historial.
        """
        try:
            hypo = self.db.query(Hypothesis).filter(Hypothesis.id == hypothesis_id).first()
            if not hypo:
                logger.error(f"Hypothesis {hypothesis_id} not found")
                return False

            old_state = hypo.status
            hypo.status = new_state
            
            # Si se aprueba, seteamos el timestamp
            if new_state == WorkflowState.APPROVED:
                hypo.approved_at = datetime.utcnow()

            # Registrar el paso
            step = WorkflowStep(
                hypothesis_id=hypothesis_id,
                state=new_state,
                actor=actor,
                notes=notes or f"Transition from {old_state} to {new_state}"
            )
            
            self.db.add(step)
            self.db.commit()
            logger.info(f"Hypothesis {hypothesis_id} transitioned: {old_state} -> {new_state} (by {actor})")
            return True
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error transitioning hypothesis: {str(e)}")
            return False
        finally:
            self.db.close()

    def get_pending_approvals(self) -> List[Hypothesis]:
        """Retorna hipótesis que requieren intervención humana."""
        db = SessionLocal()
        try:
            return db.query(Hypothesis).filter(Hypothesis.status == WorkflowState.PENDING_APPROVAL).all()
        finally:
            db.close()

    def add_step(self, target_id: int, state: str, actor: str = Actor.SYSTEM, notes: str = None):
        """Registra un paso de workflow para un target (general)."""
        db = SessionLocal()
        try:
            step = WorkflowStep(
                target_id=target_id,
                state=state,
                actor=actor,
                notes=notes
            )
            db.add(step)
            db.commit()
        finally:
            db.close()

    def cleanup_session(self, session_id: str):
        """Elimina todos los registros de una sesión temporal."""
        db = SessionLocal()
        try:
            # 1. Obtener IDs de hipótesis para borrar evidencia asociada
            hypos = db.query(Hypothesis).filter(Hypothesis.scan_id == session_id).all()
            hypo_ids = [h.id for h in hypos]
            
            if hypo_ids:
                db.query(Evidence).filter(Evidence.hypothesis_id.in_(hypo_ids)).delete(synchronize_session=False)
                db.query(WorkflowStep).filter(WorkflowStep.hypothesis_id.in_(hypo_ids)).delete(synchronize_session=False)
                db.query(Hypothesis).filter(Hypothesis.id.in_(hypo_ids)).delete(synchronize_session=False)
            
            # 2. Borrar historial general de la sesión
            db.query(WorkflowStep).filter(WorkflowStep.notes.like(f"%session {session_id}%")).delete(synchronize_session=False)
            
            db.commit()
            logger.info(f"Cleanup completed for session: {session_id}")
            return True
        except Exception as e:
            db.rollback()
            logger.error(f"Error during session cleanup: {str(e)}")
            return False
        finally:
            db.close()

# Instancia global
workflow_engine = WorkflowEngine()
