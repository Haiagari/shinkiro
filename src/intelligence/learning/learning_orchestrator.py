"""
LearningOrchestrator - Orquestador del Ciclo de Aprendizaje
Fase 2: Aprendizaje Reflexivo
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from src.intelligence.learning.decision_log import DecisionRepository, log_decision
from src.intelligence.learning.outcome_evaluator import OutcomeEvaluator, outcome_evaluator
from src.intelligence.scoring.feedback_engine import FeedbackEngine, feedback_engine
from src.intelligence.learning.false_positive_memory import FalsePositiveMemory, false_positive_memory
from src.storage.database import SessionLocal

@dataclass
class LearningMetrics:
    """Métricas del sistema de aprendizaje."""
    total_decisions: int = 0
    decision_accuracy_rate: float = 0.0
    avg_value_per_scan: float = 0.0
    false_positive_rate: float = 0.0
    signal_to_noise_ratio: float = 0.0
    time_to_first_critical: float = 0.0
    
    # Tracking
    recent_outcomes: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_decisions": self.total_decisions,
            "decision_accuracy_rate": self.decision_accuracy_rate,
            "avg_value_per_scan": self.avg_value_per_scan,
            "false_positive_rate": self.false_positive_rate,
            "signal_to_noise_ratio": self.signal_to_noise_ratio,
            "time_to_first_critical": self.time_to_first_critical
        }

class LearningOrchestrator:
    """
    Orquestador del ciclo completo de aprendizaje.
    """
    
    def __init__(self):
        # Diferimos la creación del repositorio para evitar problemas con SessionLocal en el init
        self._decision_repo = None
        self.outcome_eval = outcome_evaluator
        self.feedback = feedback_engine
        self.fp_memory = false_positive_memory
        
        self.metrics = LearningMetrics()

    @property
    def decision_log(self):
        if self._decision_repo is None:
            self._db = SessionLocal()
            self._decision_repo = DecisionRepository(self._db)
        return self._decision_repo
    
    def record_decision(self, session_id, decision_type, target, reason, context, current_weights=None) -> str:
        # Usamos los pesos actuales del feedback engine si no se pasan
        weights = current_weights or self.feedback.get_adjusted_weights()
        decision = log_decision(session_id, decision_type, target, reason, context, weights)
        self.metrics.total_decisions += 1
        return decision.id
    
    def evaluate_decision(self, decision_id, findings, time_spent, false_positive_ids=None) -> Dict[str, Any]:
        outcome = self.outcome_eval.evaluate(decision_id, findings, time_spent, false_positive_ids)
        self.metrics.recent_outcomes.append(outcome.to_dict())
        self._update_metrics()
        # Actualizar en la DB
        self.decision_log.update_outcome(decision_id, outcome.result, outcome.value_score)
        return outcome.to_dict()
    
    def evaluate_priority_decision(self, decision_id, host, host_reputation, has_critical, has_high, has_findings) -> Dict[str, Any]:
        outcome = self.outcome_eval.evaluate_priority_decision(decision_id, host, host_reputation, has_critical, has_high, has_findings)
        self.metrics.recent_outcomes.append(outcome.to_dict())
        self._update_metrics()
        self.decision_log.update_outcome(decision_id, outcome.result, outcome.value_score)
        return outcome.to_dict()
    
    def apply_feedback(self, decision_type: str, outcome_dict: Dict[str, Any]):
        result = outcome_dict.get("result")
        value_score = outcome_dict.get("value_score", 0.0)
        
        # Log del aprendizaje
        from src.core.logging import get_logger
        l_logger = get_logger("learning")
        l_logger.info(f"Applying feedback for {decision_type}. Result: {result}, Value: {value_score}")

        if result in ["success", "critical"]:
            self.feedback.adjust_from_outcome(decision_type, True, value_score)
        elif result == "failure":
            self.feedback.adjust_from_outcome(decision_type, False, value_score)
            
    def _update_metrics(self):
        outcomes = self.metrics.recent_outcomes
        if not outcomes: return
        total = len(outcomes)
        successes = sum(1 for o in outcomes if o.get("result") in ["success", "critical"])
        failures = sum(1 for o in outcomes if o.get("result") == "failure")
        self.metrics.decision_accuracy_rate = successes / total
        self.metrics.avg_value_per_scan = sum(o.get("value_score", 0) for o in outcomes) / total
        if successes + failures > 0:
            self.metrics.signal_to_noise_ratio = successes / (successes + failures)

    def get_full_feedback(self) -> Dict[str, Any]:
        return {
            "metrics": self.metrics.to_dict(),
            "weights": self.feedback.get_adjusted_weights(),
            "feedback_insights": self.feedback.get_insights(),
            "fp_stats": {}
        }
    
    def get_recommendations(self) -> List[str]:
        recs = self.feedback.get_insights().get("recommendations", [])
        if self.metrics.decision_accuracy_rate < 0.3:
            recs.append("Decisiones con baja precisión - revisar pesos")
        return recs

# Instancia global
learning_orchestrator = LearningOrchestrator()

# Alias convenience
def record_learned_decision(session_id, decision_type, target, reason, context):
    return learning_orchestrator.record_decision(session_id, decision_type, target, reason, context)

def evaluate_and_learn(decision_id, findings, time_spent):
    return learning_orchestrator.evaluate_decision(decision_id, findings, time_spent)
