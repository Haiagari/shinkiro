"""
OutcomeEvaluator - Evaluación de Decisiones
Fase 2: Aprendizaje Reflexivo
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime

class OutcomeType:
    SUCCESS = "success"           # Encontró algo valioso
    NEUTRAL = "neutral"         # Nada, pero no malgastó tiempo
    FAILURE = "failure"         # Mal decision - ruido o tiempo perdido
    CRITICAL = "critical"      # Encontró vuln crítica
    FALSE_POSITIVE = "false_positive"  # Finding descartado

@dataclass
class DecisionOutcome:
    """
    Resultado de evaluar una decisión.
    """
    decision_id: str
    result: str           # SUCCESS, NEUTRAL, FAILURE, CRITICAL
    value_score: float     # 0.0 - 1.0
    signal: str          # "critical_found", "noise", "nothing_found"
    
    # Detalles
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    false_positive_count: int = 0
    time_spent_seconds: float = 0.0
    
    # Contexto para feedback
    was_worth_it: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "result": self.result,
            "value_score": self.value_score,
            "signal": self.signal,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "was_worth_it": self.was_worth_it
        }

class OutcomeEvaluator:
    """
    Evalúa si una decisión fue buena o mala.
    """
    
    # Pesos para calcular value_score
    CRITICAL_WEIGHT = 1.0
    HIGH_WEIGHT = 0.6
    MEDIUM_WEIGHT = 0.3
    LOW_WEIGHT = 0.1
    
    # Thresholds
    NOISE_THRESHOLD = 5  # Más de 5 findings sin valor = ruido
    WORTH_IT_RATIO = 0.3  # Minimo valor para considerar worth it
    
    def evaluate(
        self,
        decision_id: str,
        findings: List[Dict[str, Any]],
        time_spent: float,
        false_positives: List[str] = None
    ) -> DecisionOutcome:
        """
        Evalúa el resultado de una decisión.
        
        Args:
            decision_id: ID de la decisión a evaluar
            findings: Lista de hallazgos encontrados
            time_spent: Tiempo invertido en segundos
            false_positives: Lista de IDs de falsos positivos conocidos
        """
        false_positives = false_positives or []
        
        # Contar por severidad
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")
        
        total_findings = len(findings)
        fp_count = sum(1 for f in findings if f.get("id") in false_positives)
        
        # Calcular value score
        value_score = (
            (critical * self.CRITICAL_WEIGHT) +
            (high * self.HIGH_WEIGHT) +
            (medium * self.MEDIUM_WEIGHT) +
            (low * self.LOW_WEIGHT)
        ) / max(1, total_findings) if findings else 0.0
        
        # Determinar resultado
        if critical > 0:
            result = OutcomeType.CRITICAL
            signal = "critical_vulnerability_found"
        elif value_score >= self.WORTH_IT_RATIO:
            result = OutcomeType.SUCCESS
            signal = "valuable_findings"
        elif total_findings > self.NOISE_THRESHOLD:
            result = OutcomeType.FAILURE
            signal = "too_much_noise"
        elif total_findings == 0:
            result = OutcomeType.NEUTRAL
            signal = "nothing_found"
        else:
            result = OutcomeType.NEUTRAL
            signal = "low_value_findings"
        
        # Calcular si valió la pena
        was_worth_it = (
            result in [OutcomeType.CRITICAL, OutcomeType.SUCCESS] or
            (time_spent < 60 and result == OutcomeType.NEUTRAL)  # Menos de 1 min = ok
        )
        
        return DecisionOutcome(
            decision_id=decision_id,
            result=result,
            value_score=value_score,
            signal=signal,
            findings_count=total_findings,
            critical_count=critical,
            high_count=high,
            false_positive_count=fp_count,
            time_spent_seconds=time_spent,
            was_worth_it=was_worth_it
        )
    
    def evaluate_priority_decision(
        self,
        decision_id: str,
        host: str,
        host_reputation: float,
        has_critical: bool,
        has_high: bool,
        has_findings: bool
    ) -> DecisionOutcome:
        """
        Evalúa una decisión de priorización de host.
        """
        if has_critical:
            result = OutcomeType.CRITICAL
            value_score = 1.0
            signal = "critical_found_on_prioritized_host"
        elif has_high:
            result = OutcomeType.SUCCESS
            value_score = 0.8
            signal = "high_found_on_prioritized_host"
        elif has_findings:
            result = OutcomeType.NEUTRAL
            value_score = 0.4
            signal = "some_findings_on_prioritized_host"
        else:
            # Sin hallazgos - evaluar si la reputación lo justificaba
            if host_reputation >= 7.0:
                result = OutcomeType.NEUTRAL
                value_score = 0.2
                signal = "high_reputation_but_no_findings"
            else:
                result = OutcomeType.FAILURE
                value_score = 0.0
                signal = "wasted_scan"
        
        return DecisionOutcome(
            decision_id=decision_id,
            result=result,
            value_score=value_score,
            signal=signal,
            findings_count=1 if has_findings else 0,
            critical_count=1 if has_critical else 0,
            high_count=1 if has_high else 0,
            was_worth_it=result != OutcomeType.FAILURE
        )
    
    def get_statistics(self, outcomes: List[DecisionOutcome]) -> Dict[str, Any]:
        """
        Calcula estadísticas de un conjunto de outcomes.
        """
        if not outcomes:
            return {"count": 0}
        
        total = len(outcomes)
        successes = sum(1 for o in outcomes if o.result in [OutcomeType.SUCCESS, OutcomeType.CRITICAL])
        failures = sum(1 for o in outcomes if o.result == OutcomeType.FAILURE)
        
        return {
            "count": total,
            "success_rate": successes / total,
            "failure_rate": failures / total,
            "avg_value_score": sum(o.value_score for o in outcomes) / total,
            "critical_found": sum(o.critical_count for o in outcomes),
            "false_positives": sum(o.false_positive_count for o in outcomes)
        }

# Instancia global
outcome_evaluator = OutcomeEvaluator()