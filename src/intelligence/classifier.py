"""
Intelligent Inference Engine (OzyRecon v7.5 - Intelligence Formalization Layer)
Converts raw metadata into functional intelligence with full traceability.
"""

import re
import logging
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SemanticClassifier:
    """
    Formalized inference engine that uses structured rules to classify assets.
    Provides 'Explainability' through reasoning traces.
    """

    def __init__(self, rules_path: str = "resources/rules/semantic_rules.yaml"):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
        logger.info(f"IntelligentInferenceEngine initialized with {len(self.rules.get('roles', {}))} roles and {len(self.rules.get('labels', {}))} label rules.")

    def _load_rules(self) -> Dict[str, Any]:
        """Loads semantic rules from YAML."""
        try:
            if self.rules_path.exists():
                with open(self.rules_path, "r") as f:
                    return yaml.safe_load(f)
            else:
                logger.warning(f"Rules file not found at {self.rules_path}. Using fallback defaults.")
                return self._get_fallback_rules()
        except Exception as e:
            logger.error(f"Error loading semantic rules: {e}")
            return self._get_fallback_rules()

    def _get_fallback_rules(self) -> Dict[str, Any]:
        """Hardcoded defaults if YAML fails."""
        return {
            "roles": {"API": {"keywords": ["api"], "confidence_step": 0.4, "impact": "HIGH"}},
            "labels": {"gate_admin": {"patterns": ["admin"], "signals": ["domain"], "weight": 0.5, "impact": "CRITICAL"}}
        }

    def classify_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for asset classification.
        Returns labels, confidence, impact, and a detailed trace.
        """
        domain = asset_data.get("domain", "").lower()
        title = asset_data.get("title", "").lower()
        techs = [t.lower() for t in (asset_data.get("technologies", []) or [])]
        headers = str(asset_data.get("headers", {})).lower()

        inferred_labels = []
        confidence = 0.0
        impact = "LOW"
        reasoning = []
        trace = []

        # 1. Role-based matching (Keyword match)
        roles_rules = self.rules.get("roles", {})
        for role_name, config in roles_rules.items():
            for kw in config.get("keywords", []):
                if kw in domain or kw in title:
                    label = f"role:{role_name.lower()}"
                    inferred_labels.append(label)
                    step = config.get("confidence_step", 0.2)
                    confidence += step
                    msg = f"Domain/Title contains keyword '{kw}'"
                    reasoning.append(msg)
                    trace.append({
                        "type": "role_match",
                        "rule": role_name,
                        "signal": "domain/title",
                        "match": kw,
                        "contribution": step
                    })
                    if self._priority_value(config.get("impact", "LOW")) > self._priority_value(impact):
                        impact = config.get("impact", "LOW")

        # 2. Label-based matching (Regex match with Priority)
        labels_rules = self.rules.get("labels", {})
        # Sort labels by priority (descending) to allow overrides
        sorted_labels = sorted(
            labels_rules.items(), 
            key=lambda x: x[1].get("priority", 0), 
            reverse=True
        )

        for label_name, config in sorted_labels:
            patterns = config.get("patterns", [])
            signals = config.get("signals", ["domain"])
            weight = config.get("weight", 0.3)
            priority = config.get("priority", 0)
            
            for pattern in patterns:
                matched = False
                if "domain" in signals and re.search(pattern, domain): matched = True
                if "title" in signals and re.search(pattern, title): matched = True
                if "headers" in signals and re.search(pattern, headers): matched = True
                
                if matched:
                    # Logic: If a higher priority label already matched something conflicting, 
                    # we could skip. But for now, we just record the priority.
                    inferred_labels.append(label_name)
                    confidence += weight
                    msg = f"Matched pattern '{pattern}' (P:{priority}) for label '{label_name}'"
                    reasoning.append(msg)
                    trace.append({
                        "type": "label_match",
                        "rule": label_name,
                        "pattern": pattern,
                        "priority": priority,
                        "contribution": weight
                    })
                    if self._priority_value(config.get("impact", "LOW")) > self._priority_value(impact):
                        impact = config.get("impact", "LOW")
                    break

        # 3. Promotion Rules (Correlation Motor)
        promotion_rules = self.rules.get("promotion_rules", [])
        for rule in promotion_rules:
            cond_labels = rule.get("condition", {}).get("labels", [])
            # Check if all condition labels are met
            if all(lbl in inferred_labels for lbl in cond_labels):
                res_label = rule.get("result_label")
                inferred_labels.append(res_label)
                confidence += 0.2 # Boost confidence for multi-signal validation
                reasoning.append(f"Promoted to '{res_label}' due to signal correlation: {rule.get('name')}")
                trace.append({
                    "type": "promotion",
                    "rule": rule.get("name"),
                    "correlation": cond_labels,
                    "contribution": 0.2
                })
                if self._priority_value(rule.get("impact", "LOW")) > self._priority_value(impact):
                    impact = rule.get("impact", "LOW")

        # Deduplicate and finalize
        inferred_labels = list(set(inferred_labels))
        confidence = min(1.0, confidence)

        return {
            "labels": inferred_labels,
            "confidence": round(confidence, 2),
            "impact": impact,
            "reasoning": list(set(reasoning))[:5],
            "trace": trace
        }

    def _priority_value(self, p: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(p, 0)

# Global Instance
semantic_classifier = SemanticClassifier()
