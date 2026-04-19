"""
OzyRecon Intelligence Module
Análisis de severidad, deduplicación, correlación y detección de novedades.
"""

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

__all__ = [
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
]