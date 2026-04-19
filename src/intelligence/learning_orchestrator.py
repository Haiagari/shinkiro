"""
LearningOrchestrator - Orquestador del Ciclo de Aprendizaje
Fase 2: Aprendizaje Reflexivo
Combina DecisionLog + OutcomeEvaluator + FeedbackEngine + FalsePositiveMemory
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from src.intelligence.decision_log import DecisionLog, log_decision
from src.intelligence.outcome_evaluator import OutcomeEvaluator, outcome_evaluator
from src.intelligence.feedback_engine import FeedbackEngine, feedback_engine
from src.intelligence.false_positive_memory import FalsePositiveMemory, false_positive_memory

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
    
    Flujo:
    1. Sistema toma decisión → DecisionLog
    2. Se ejecuta acción
    3. OutcomeEvaluator analiza resultado
    4. FeedbackEngine ajusta pesos
    5. Sistema mejora decisiones futuras
    """
    
    def __init__(self):
        self.decision_log = DecisionLog()
        self.outcome_eval = outcome_evaluator
        self.feedback = feedback_engine
        self.fp_memory = false_positive_memory
        
        self.metrics = LearningMetrics()
    
    # =========================================================================
    # FASE 1: Registrar decisión
    # =========================================================================
    
    def record_decision(
        self,
        session_id: str,
        decision_type: str,
        target: str,
        reason: str,
        context: Dict[str, Any],
        current_weights: Optional[Dict[str, float]] = None
    ) -> str:
        """
        Registra una decisión antes de ejecutarla.
        Returns: decision_id
        """
        decision = log_decision(
            session_id=session_id,
            decision_type=decision_type,
            target=target,
            reason=reason,
            context=context,
            weights=current_weights or {}
        )
        self.metrics.total_decisions += 1
        return decision.id
    
    # =========================================================================
    # FASE 2: Evaluar resultado
    # =========================================================================
    
    def evaluate_decision(
        self,
        decision_id: str,
        findings: List[Dict[str, Any]],
        time_spent: float,
        false_positive_ids: List[str] = None
    ) -> Dict[str, Any]:
        """
        Evalúa el resultado de una decisión.
        Returns: outcome dict
        """
        outcome = self.outcome_eval.evaluate(
            decision_id=decision_id,
            findings=findings,
            time_spent=time_spent,
            false_positives=false_positive_ids or []
        )
        
        # Guardar en métricas
        self.metrics.recent_outcomes.append(outcome.to_dict())
        if len(self.metrics.recent_outcomes) > 100:
            self.metrics.recent_outcomes = self.metrics.recent_outcomes[-100:]
        
        # Actualizar métricas globales
        self._update_metrics()
        
        return outcome.to_dict()
    
    def evaluate_priority_decision(
        self,
        decision_id: str,
        host: str,
        host_reputation: float,
        has_critical: bool,
        has_high: bool,
        has_findings: bool
    ) -> Dict[str, Any]:
        """
        Evalúa una decisión de priorización.
        """
        outcome = self.outcome_eval.evaluate_priority_decision(
            decision_id=decision_id,
            host=host,
            host_reputation=host_reputation,
            has_critical=has_critical,
            has_high=has_high,
            has_findings=has_findings
        )
        
        self.metrics.recent_outcomes.append(outcome.to_dict())
        self._update_metrics()
        
        return outcome.to_dict()
    
    # =========================================================================
    # FASE 3: Feedback - Ajustar pesos
    # =========================================================================
    
    def apply_feedback(
        self,
        decision_type: str,
        outcome_dict: Dict[str, Any]
    ):
        """
        Ajusta el sistema basado en el outcome.
        """
        result = outcome_dict.get("result")
        value_score = outcome_dict.get("value_score", 0.0)
        
        if result in ["success", "critical"]:
            # Decisión buena - aumentar peso
            self.feedback.adjust_from_outcome(decision_type, True, value_score)
        elif result == "failure":
            # Decisión mala - reducir peso
            self.feedback.adjust_from_outcome(decision_type, False, value_score)
    
    # =========================================================================
    # FASE 4: Higiene - Aprender de FP
    # =========================================================================
    
    def register_false_positive(
        self,
        finding_id: str,
        tool: str,
        finding_details: Dict[str, Any]
    ):
        """
        Registra un finding como falso positivo.
        """
        self.fp_memory.register_discovery(finding_id, tool, finding_details)
    
    def get_skip_list(self, tool: str = None) -> List[str]:
        """
        Obtiene lista de patrones a evitar.
        """
        return self.fp_memory.get_avoid_list(tool)
    
    # =========================================================================
    # Utilidades
    # =========================================================================
    
    def _update_metrics(self):
        """Actualiza métricas globales."""
        outcomes = self.metrics.recent_outcomes
        if not outcomes:
            return
        
        total = len(outcomes)
        successes = sum(
            1 for o in outcomes 
            if o.get("result") in ["success", "critical"]
        )
        failures = sum(1 for o in outcomes if o.get("result") == "failure")
        fps = sum(1 for o in outcomes if o.get("result") == "false_positive")
        
        self.metrics.decision_accuracy_rate = successes / total if total > 0 else 0.0
        self.metrics.false_positive_rate = fps / total if total > 0 else 0.0
        
        value_scores = [o.get("value_score", 0) for o in outcomes]
        self.metrics.avg_value_per_scan = (
            sum(value_scores) / total if total > 0 else 0.0
        )
        
        # Signal to noise
        if successes + failures > 0:
            self.metrics.signal_to_noise_ratio = (
                successes / (successes + failures)
            )
    
    def get_full_feedback(self) -> Dict[str, Any]:
        """
        Retorna el estado completo del aprendizaje.
        """
        return {
            "metrics": self.metrics.to_dict(),
            "weights": self.feedback.get_adjusted_weights(),
            "feedback_insights": self.feedback.get_insights(),
            "fp_stats": {
                tool: self.fp_memory.get_tool_statistics(tool)
                for tool in ["nuclei", "dalfox", "sqlmap"]
            }
        }
    
    def get_recommendations(self) -> List[str]:
        """
        Genera recomendaciones basadas en el aprendizaje.
        """
        recs = []
        
        # Por métricas
        if self.metrics.decision_accuracy_rate < 0.3:
            recs.append("Decisiones seldom acertadas - revisar estrategia")
        
        if self.metrics.false_positive_rate > 0.3:
            recs.append("Alto rate de FP - considerar más filtros")
        
        # Por feedback
        recs.extend(self.feedback.get_insights().get("recommendations", []))
        
        return recs

# Instancia global
learning_orchestrator = LearningOrchestrator()

# Alias convenience
def record_learned_decision(session_id, decision_type, target, reason, context):
    return learning_orchestrator.record_decision(session_id, decision_type, target, reason, context)

def evaluate_and_learn(decision_id, findings, time_spent):
    outcome = learning_orchestrator.evaluate_decision(decision_id, findings, time_spent)
    # Auto apply feedback
    learning_orchestrator.apply_feedback(
        learning_orchestrator.decision_log.get_by_session(
            # Get decision type from stored
        ).decision_type if hasattr(learning_orchestrator.decision_log, 'get_by_session') else "unknown",
        outcome
    )
    return outcome