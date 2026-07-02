"""
PromptWall Intelligence Module
Análisis de severidad, deduplicación, correlación y detección de novedades.
"""

# core
from .core.analyzer import (
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
from .core.intelligence import run_intelligence
from .core.classifier import semantic_classifier

# scoring
from .scoring.scoring_engine import get_scoring_engine, ScoringEngine, CriticalityScore
from .scoring.priority import PriorityEngine
from .scoring.feedback_engine import (
    FeedbackEngine,
    ScoringWeights,
    feedback_engine,
)

# learning
from .learning.learning_engine import LearningEngine, MIN_OBSERVATIONS, run_learning
from .learning.learning_orchestrator import (
    LearningOrchestrator,
    LearningMetrics,
    learning_orchestrator,
    record_learned_decision,
    evaluate_and_learn,
)
from .learning.decision_log import (
    DecisionRepository,
    DecisionType,
    Decision,
    log_decision,
)
from .learning.outcome_evaluator import (
    OutcomeEvaluator,
    OutcomeType,
    DecisionOutcome,
    outcome_evaluator,
)
from .learning.false_positive_memory import (
    FalsePositiveMemory,
    FalsePositivePattern,
    false_positive_memory,
)
from .learning.sync_manager import SyncManager

# enrichment
from .enrichment.enrichment import enrich_hosts
from .enrichment.infrastructure import InfraEnricher, infra_enricher
from .enrichment.secret_finder import SecretFinder, secret_finder
from .enrichment.exploit_advisor import ExploitAdvisor, exploit_advisor

# analysis
from .analysis.ai_analyzer import ai_analyst, AIAnalyst
from .analysis.logic_analyzer import LogicAnalyzer
from .analysis.path_analyzer import PathAnalyzer, get_attack_paths
from .analysis.graph_builder import GraphBuilder, graph_builder
from .analysis.evidence_linker import EvidenceLinker, evidence_linker

# autonomy
from .autonomy.autonomy import (
    AutonomyPlanner,
    AutonomyPlan,
    build_autonomy_plan,
)
from .autonomy.autonomy_engine import AutonomyEngine, autonomy_engine
from .autonomy.planner import ReconPlanner, recon_planner
from .autonomy.recommendations import generate_arch_recommendations
from .autonomy.brief import generate_intelligence, IntelligenceBrief, IntelligenceGenerator
from .autonomy.dashboard import show_dashboard, IntelligenceDashboard

# pipeline
from .pipeline.orchestrator import DiscoveryOrchestrator
from .pipeline.novelty import NoveltyAlerter, novelty_alerter
from .pipeline.collaboration import (
    write_collaboration_manifest,
    append_collaboration_operator,
    read_collaboration_manifest,
)

# export
from .export.exporter import SIEMExporter, siem_exporter

__all__ = [
    # core/analyzer
    'SeverityAnalyzer',
    'SeverityResult',
    'severity_analyzer',
    'analyze_severity',
    'Deduplicator',
    'deduplicator',
    'deduplicate_findings',
    'CorrelationEngine',
    'correlation_engine',
    'NoveltyDetector',
    'novelty_detector',
    # core/intelligence
    'run_intelligence',
    # core/classifier
    'semantic_classifier',

    # scoring
    'get_scoring_engine',
    'ScoringEngine',
    'CriticalityScore',
    'PriorityEngine',
    'FeedbackEngine',
    'ScoringWeights',
    'feedback_engine',

    # learning
    'LearningEngine',
    'MIN_OBSERVATIONS',
    'run_learning',
    'LearningOrchestrator',
    'LearningMetrics',
    'learning_orchestrator',
    'record_learned_decision',
    'evaluate_and_learn',
    'DecisionRepository',
    'DecisionType',
    'Decision',
    'log_decision',
    'OutcomeEvaluator',
    'OutcomeType',
    'DecisionOutcome',
    'outcome_evaluator',
    'FalsePositiveMemory',
    'FalsePositivePattern',
    'false_positive_memory',
    'SyncManager',

    # enrichment
    'enrich_hosts',
    'InfraEnricher',
    'infra_enricher',
    'SecretFinder',
    'secret_finder',
    'ExploitAdvisor',
    'exploit_advisor',

    # analysis
    'ai_analyst',
    'AIAnalyst',
    'LogicAnalyzer',
    'PathAnalyzer',
    'get_attack_paths',
    'GraphBuilder',
    'graph_builder',
    'EvidenceLinker',
    'evidence_linker',

    # autonomy
    'AutonomyPlanner',
    'AutonomyPlan',
    'build_autonomy_plan',
    'AutonomyEngine',
    'autonomy_engine',
    'ReconPlanner',
    'recon_planner',
    'generate_arch_recommendations',
    'generate_intelligence',
    'IntelligenceBrief',
    'IntelligenceGenerator',
    'show_dashboard',
    'IntelligenceDashboard',

    # pipeline
    'DiscoveryOrchestrator',
    'NoveltyAlerter',
    'novelty_alerter',
    'write_collaboration_manifest',
    'append_collaboration_operator',
    'read_collaboration_manifest',

    # export
    'SIEMExporter',
    'siem_exporter',
]
