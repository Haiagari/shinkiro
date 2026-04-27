"""
OzyRecon Scoring Engine - Phase 5
Intelligent Scoring System for Discovered Assets
Assigns Criticality Index (0-100) based on service-specific heuristics.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.core.logging import get_logger

logger = get_logger("scoring_engine")


@dataclass
class CriticalityScore:
    """Criticality Index for a discovered asset."""
    
    service_type: str
    index: int  # 0-100
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    base_score: int
    score_breakdown: dict = field(default_factory=dict)
    modifiers: dict = field(default_factory=dict)
    recommendations: list = field(default_factory=list)
    source: str = "heuristic"
    asset_identifier: str = ""
    
    def to_summary_row(self) -> dict:
        """Convert to dictionary for Rich table display."""
        return {
            "service": self.service_type,
            "index": self.index,
            "severity": self.severity,
            "base_score": self.base_score,
            "modifiers_count": len(self.modifiers),
            "recommendations": "; ".join(self.recommendations[:2]) if self.recommendations else "-",
        }


class ScoringEngine:
    """
    Intelligent scoring engine that evaluates discovered assets.
    
    Loads rules from resources/rules/scoring_rules.yaml and applies
    service-specific heuristics to calculate Criticality Index (0-100).
    """
    
    # Severity thresholds
    SEVERITY_THRESHOLDS = {
        "critical": 80,
        "high": 60,
        "medium": 40,
        "low": 20,
    }
    
    def __init__(self, rules_path: str = "resources/rules/scoring_rules.yaml"):
        """
        Initialize ScoringEngine with rules from YAML file.
        
        Args:
            rules_path: Path to scoring_rules.yaml file
        """
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
        self._scores_cache: list[CriticalityScore] = []
        logger.debug(f"ScoringEngine initialized with {len(self.rules.get('services', {}))} service rules")
    
    def _load_rules(self) -> dict:
        """Load scoring rules from YAML file."""
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                rules = yaml.safe_load(f)
            logger.info(f"Loaded scoring rules from {self.rules_path}")
            return rules
        except FileNotFoundError:
            logger.error(f"Rules file not found: {self.rules_path}")
            return self._get_default_rules()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing rules YAML: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> dict:
        """Return minimal default rules when YAML is unavailable."""
        return {
            "services": {
                "apache_php": {"base_score": 45, "factors": [], "recommendations": []},
                "tomcat": {"base_score": 65, "factors": [], "recommendations": []},
                "smb": {"base_score": 50, "factors": [], "recommendations": []},
                "s3_bucket": {"base_score": 55, "factors": [], "recommendations": []},
                "jenkins": {"base_score": 60, "factors": [], "recommendations": []},
                "redis": {"base_score": 55, "factors": [], "recommendations": []},
            },
            "thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 40,
                "low": 20,
            },
        }
    
    def get_severity_name(self, index: int) -> str:
        """
        Map Criticality Index to severity name.
        
        Args:
            index: Criticality Index (0-100)
            
        Returns:
            Severity name: CRITICAL, HIGH, MEDIUM, LOW, or INFO
        """
        if index >= self.SEVERITY_THRESHOLDS["critical"]:
            return "CRITICAL"
        elif index >= self.SEVERITY_THRESHOLDS["high"]:
            return "HIGH"
        elif index >= self.SEVERITY_THRESHOLDS["medium"]:
            return "MEDIUM"
        elif index >= self.SEVERITY_THRESHOLDS["low"]:
            return "LOW"
        else:
            return "INFO"
    
    def score_asset(self, service_info: dict[str, Any]) -> CriticalityScore:
        """
        Score a discovered asset and return CriticalityScore.
        
        Args:
            service_info: Dict containing service information:
                - service_type: str (e.g., "apache_php", "tomcat", "redis")
                - identifier: str (e.g., "192.168.1.1:80")
                - details: dict with service-specific factors
                
        Returns:
            CriticalityScore object with index, severity, and recommendations
        """
        service_type = service_info.get("service_type", "unknown")
        identifier = service_info.get("identifier", "")
        details = service_info.get("details", {})
        
        # Get service rules
        services_rules = self.rules.get("services", {})
        service_rules = services_rules.get(service_type, {"base_score": 50, "factors": [], "recommendations": []})
        
        # Calculate base score
        base_score = service_rules.get("base_score", 50)
        
        # Apply modifiers based on detected factors
        total_modifier = 0
        score_breakdown = {}
        modifiers_applied = {}
        active_recommendations = []
        
        for factor in service_rules.get("factors", []):
            factor_name = factor.get("name", "")
            factor_weight = factor.get("weight", 0)
            factor_conditions = factor.get("conditions", [])
            
            # Check each condition against detected details
            for condition in factor_conditions:
                condition_value = condition.get("value", "")
                modifier = condition.get("modifier", 0)
                
                # Check if this condition is present in service details
                if self._check_condition(condition_value, details):
                    total_modifier += modifier
                    modifiers_applied[condition_value] = modifier
                    
                    # Track score breakdown
                    score_breakdown[factor_name] = {
                        "condition": condition_value,
                        "modifier": modifier,
                        "weight": factor_weight,
                    }
        
        # Calculate final index
        raw_index = base_score + total_modifier
        criticality_index = max(0, min(100, raw_index))  # Clamp to 0-100
        
        # Determine severity
        severity = self.get_severity_name(criticality_index)
        
        # Generate recommendations based on active modifiers
        recommendations = self._generate_recommendations(service_rules, modifiers_applied)
        
        # Create score object
        score = CriticalityScore(
            service_type=service_type,
            index=criticality_index,
            severity=severity,
            base_score=base_score,
            score_breakdown=score_breakdown,
            modifiers=modifiers_applied,
            recommendations=recommendations,
            source="heuristic",
            asset_identifier=identifier,
        )
        
        # Cache for summary generation
        self._scores_cache.append(score)
        
        logger.debug(f"Scored {service_type} @ {identifier}: index={criticality_index}, severity={severity}")
        return score
    
    def _check_condition(self, condition_value: str, details: dict) -> bool:
        """
        Check if a condition is present in service details.
        
        Args:
            condition_value: Value to check (e.g., "phpinfo", "SMB1")
            details: Service details dict
            
        Returns:
            True if condition is detected
        """
        details_str = str(details).lower()
        condition_lower = condition_value.lower()
        
        # Check direct string matches in details
        if condition_lower in details_str:
            return True
        
        # Check specific detail fields
        check_fields = ["version", "config", "paths", "exposed", "method", "acl"]
        for field in check_fields:
            if field in details:
                field_value = str(details[field]).lower()
                if condition_lower in field_value:
                    return True
        
        return False
    
    def _generate_recommendations(
        self, service_rules: dict, modifiers_applied: dict
    ) -> list[str]:
        """
        Generate recommendations based on active modifiers.
        
        Args:
            service_rules: Service rules dict with recommendations
            modifiers_applied: Dict of applied modifiers
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        base_recommendations = service_rules.get("recommendations", [])
        
        # Add base recommendations
        recommendations.extend(base_recommendations[:2])
        
        # Add dynamic recommendations based on active modifiers
        critical_conditions = ["phpinfo", "env_file", "default_creds", "writable", "allputops", "accessible"]
        for condition in critical_conditions:
            if condition in modifiers_applied:
                if condition == "phpinfo":
                    recommendations.append("Critical: Information disclosure via phpinfo()")
                elif condition == "env_file":
                    recommendations.append("Critical: Secrets exposure via .env file")
                elif condition == "default_creds":
                    recommendations.append("Critical: Default credentials detected")
                elif condition == "writable":
                    recommendations.append("Critical: Writable share - code execution possible")
                elif condition == "allputops":
                    recommendations.append("Critical: Full bucket control via allputops")
                elif condition == "accessible":
                    recommendations.append("Critical: Admin interface accessible")
        
        # Deduplicate while preserving order
        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)
        
        return unique_recs[:3]  # Limit to 3 recommendations
    
    def score_batch(self, services: list[dict[str, Any]]) -> list[CriticalityScore]:
        """
        Score multiple assets in batch.
        
        Args:
            services: List of service_info dicts
            
        Returns:
            List of CriticalityScore objects
        """
        return [self.score_asset(service) for service in services]
    
    def get_priority_queue(self, limit: int = 10) -> list[CriticalityScore]:
        """
        Get highest-priority assets for validation.
        
        Args:
            limit: Maximum number of items to return
            
        Returns:
            List of CriticalityScore objects sorted by index descending
        """
        sorted_scores = sorted(self._scores_cache, key=lambda x: x.index, reverse=True)
        return sorted_scores[:limit]
    
    def get_summary_table(self) -> list[dict]:
        """
        Get all scores as summary rows for Rich table display.
        
        Returns:
            List of dicts suitable for Rich Table
        """
        return [score.to_summary_row() for score in self._scores_cache]


# Singleton instance for easy access
_scoring_engine: ScoringEngine | None = None


def get_scoring_engine(rules_path: str = "resources/rules/scoring_rules.yaml") -> ScoringEngine:
    """Get or create the singleton ScoringEngine instance."""
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine(rules_path)
    return _scoring_engine