"""
OzyRecon Intelligence Module
Análisis de severidad, deduplicación, correlación y detección de novedades.
"""

# Fase 1: Inteligencia adaptativa
from .analyzer import (
    SeverityAnalyzer,
    SeverityResult,
    Deduplicator,
    CorrelationEngine,
    NoveltyDetector,
    severity_analyzer,
    deduplicator,
    correlation_engine,
    novelty_detector,
    analyze_severity,
    deduplicate_findings,
)

# Fase 2: Aprendizaje reflexivo
from .learning_orchestrator import (
    LearningOrchestrator,
    LearningMetrics,
    learning_orchestrator,
    record_learned_decision,
    evaluate_and_learn,
)

from .decision_log import (
    DecisionRepository,
    DecisionType,
    Decision,
    log_decision,
)

from .outcome_evaluator import (
    OutcomeEvaluator,
    OutcomeType,
    DecisionOutcome,
    outcome_evaluator,
)

from .feedback_engine import (
    FeedbackEngine,
    ScoringWeights,
    feedback_engine,
)

from .false_positive_memory import (
    FalsePositiveMemory,
    FalsePositivePattern,
    false_positive_memory,
)

from .autonomy import (
    AutonomyPlanner,
    AutonomyPlan,
    build_autonomy_plan,
)

__all__ = [
    # ===== FASE 1: Inteligencia Adaptativa =====
    # Severity
    'SeverityAnalyzer',
    'SeverityResult',
    'severity_analyzer',
    'analyze_severity',
    # Deduplication
    'Deduplicator',
    'deduplicator',
    'deduplicate_findings',
    # Correlation
    'CorrelationEngine',
    'correlation_engine',
    # Novelty
    'NoveltyDetector',
    'novelty_detector',
    
    # ===== FASE 2: Aprendizaje Reflexivo =====
    # Orchestrator
    'LearningOrchestrator',
    'LearningMetrics',
    'learning_orchestrator',
    'record_learned_decision',
    'evaluate_and_learn',
    # Decision Log
    'DecisionRepository',
    'DecisionType',
    'Decision',
    'log_decision',
    # Outcome Evaluator
    'OutcomeEvaluator',
    'OutcomeType',
    'DecisionOutcome',
    'outcome_evaluator',
    # Feedback Engine
    'FeedbackEngine',
    'ScoringWeights',
    'feedback_engine',
    # False Positive Memory
    'FalsePositiveMemory',
    'FalsePositivePattern',
    'false_positive_memory',
    # ===== FASE 4: Autonomía Segura =====
    'AutonomyPlanner',
    'AutonomyPlan',
    'build_autonomy_plan',
]
