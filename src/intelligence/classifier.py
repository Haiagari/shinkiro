"""
Semantic Classifier Engine (OzyRecon v7 - Phase 5)
Infers the functional role of an asset based on rich metadata.
"""

import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SemanticClassifier:
    """
    Analyzes asset metadata to assign functional roles and impact levels.
    """

    # Functional Roles
    ROLES = {
        "MANAGEMENT": ["cpanel", "whm", "webmail", "phpmyadmin", "plesk", "directadmin"],
        "AUTH": ["login", "signin", "sso", "auth", "portal", "identity"],
        "API": ["api", "v1", "v2", "v3", "graphql", "rest", "soap", "swagger", "docs"],
        "DEVELOPMENT": ["dev", "staging", "test", "qa", "internal", "jenkins", "gitlab", "bitbucket"],
        "COMMERCE": ["shop", "store", "checkout", "cart", "payment", "billing"],
        "CMS": ["wordpress", "drupal", "joomla", "magento", "shopify"]
    }

    # Semantic Labels Mapping (Keyword in Title/Domain -> Label)
    LABEL_RULES = [
        (r"login|sign.?in|acceso", "gate_auth", "HIGH"),
        (r"admin|dashboard|panel|gesti.n", "gate_admin", "CRITICAL"),
        (r"api|endpoint|swagger|graphql", "api_surface", "HIGH"),
        (r"dev|staging|test|qa|sandbox", "non_prod_env", "MEDIUM"),
        (r"mail|webmail|outlook|exchange", "comm_surface", "MEDIUM"),
        (r"storage|bucket|s3|cloud", "data_storage", "HIGH"),
        (r"checkout|pago|pay|cart", "transaccional", "CRITICAL")
    ]

    def classify_asset(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Infers the role and labels for an asset based on its metadata.
        """
        domain = asset_data.get("domain", "").lower()
        title = asset_data.get("title", "").lower()
        techs = [t.lower() for t in (asset_data.get("technologies", []) or [])]
        
        inferred_labels = []
        confidence = 0.0
        impact = "LOW"
        reasoning = []

        # 1. Domain-based classification
        for role, keywords in self.ROLES.items():
            for kw in keywords:
                if kw in domain:
                    inferred_labels.append(f"role:{role.lower()}")
                    reasoning.append(f"Domain contains keyword '{kw}'")
                    confidence += 0.3

        # 2. Rule-based label matching (Regex on Title/Domain)
        for pattern, label, imp in self.LABEL_RULES:
            if re.search(pattern, domain) or re.search(pattern, title):
                inferred_labels.append(label)
                reasoning.append(f"Matched pattern '{pattern}' in domain/title")
                confidence += 0.4
                if self._priority_value(imp) > self._priority_value(impact):
                    impact = imp

        # 3. Tech-based enrichment
        for t in techs:
            if "wordpress" in t or "cpanel" in t:
                inferred_labels.append("management_surface")
                reasoning.append(f"Detected sensitive technology: {t}")
                confidence += 0.5
                impact = "HIGH"

        # Deduplicate and Cap Confidence
        inferred_labels = list(set(inferred_labels))
        confidence = min(1.0, confidence)

        return {
            "labels": inferred_labels,
            "confidence": confidence,
            "impact": impact,
            "reasoning": reasoning[:3] # Keep it concise
        }

    def _priority_value(self, p: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(p, 0)

# Global Instance
semantic_classifier = SemanticClassifier()
