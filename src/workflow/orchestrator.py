"""
Workflow Orchestrator - Ejecución de validaciones aprobadas v5.0
"""

from typing import List
from src.storage.database import SessionLocal
from src.storage.models import Hypothesis
from src.workflow.states import WorkflowState, Actor
from src.workflow.engine import workflow_engine
from src.evidence.engine import evidence_engine
from src.core.logging import get_logger

# Importación dinámica de validadores para evitar ciclos
from src.validation.http import HTTPValidator
from src.validation.infra import InfraValidator
from src.validation.automation import AutomationValidator

logger = get_logger('workflow_orchestrator')

class WorkflowOrchestrator:
    def __init__(self):
        self.validators = {
            "HTTP": HTTPValidator(),
            "INFRA": InfraValidator(),
            "AUTOMATION": AutomationValidator(),
            # "AUTH": AuthValidator(), # v5.1
        }

    def process_approved(self):
        """Busca y procesa hipótesis aprobadas."""
        db = SessionLocal()
        try:
            approved = db.query(Hypothesis).filter(Hypothesis.status == WorkflowState.APPROVED).all()
            if not approved:
                logger.info("No approved hypotheses to process")
                return

            for hypo in approved:
                self.validate_hypothesis(hypo)
        finally:
            db.close()

    def validate_hypothesis(self, hypo: Hypothesis):
        """Ejecuta el validador correspondiente para una hipótesis."""
        logger.info(f"Starting validation for hypothesis {hypo.id} ({hypo.type})")
        
        # Mover a estado VALIDATING
        workflow_engine.transition_hypothesis(hypo.id, WorkflowState.VALIDATING, notes="Starting automated validation")

        # Selección inteligente de validador (v5.2-v5.4 update)
        v_type = "HTTP"
        if hypo.type == "EXPOSED_DATABASE":
            v_type = "INFRA"
        elif hypo.type == "AUTOMATION_PANEL":
            v_type = "AUTOMATION"
            
        validator = self.validators.get(v_type, self.validators["HTTP"])
        
        # Convertir modelo a dict para el validador
        hypo_dict = {
            "id": hypo.id,
            "type": hypo.type,
            "url": hypo.url,
            "confidence": hypo.confidence,
            "signals": hypo.signals
        }

        result = validator.validate(hypo_dict)

        # Registrar evidencia
        for ev in result.evidence:
            evidence_engine.record_evidence(
                hypothesis_id=hypo.id,
                evidence_type=ev["type"],
                data=ev["data"],
                metadata=ev["metadata"]
            )

        # Finalizar transición
        new_state = WorkflowState.VALIDATED if result.status == "confirmed" else WorkflowState.ANALYZED
        workflow_engine.transition_hypothesis(
            hypo.id, 
            new_state, 
            notes=f"Validation finished: {result.status}. {result.notes}"
        )
        
        # Actualizar confianza en el modelo
        db = SessionLocal()
        try:
            h = db.query(Hypothesis).filter(Hypothesis.id == hypo.id).first()
            h.confidence = result.confidence_after
            db.commit()
        finally:
            db.close()

# Instancia global
orchestrator = WorkflowOrchestrator()
