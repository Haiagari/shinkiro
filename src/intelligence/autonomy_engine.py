"""
PromptWall Autonomous Engine (v8.3.2 - Pilot Mode)
Decides next tactical actions based on semantic signals.
"""

import logging
from typing import List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger("intelligence.autonomy")

@dataclass
class TacticalAction:
    capability: str
    target: str
    reason: str
    priority: int = 1  # 1 (low) to 5 (critical)
    params: Dict[str, Any] = None

class AutonomyEngine:
    """
    The "Brain" that decides what to do next without human intervention.
    Maps semantic labels to tactical capabilities.
    """
    
    # Tactical Mapping: Label -> (Capability, Priority, Reason)
    STRATEGY_MAP = {
        "gate_admin": ("template_scan", 5, "Exposed administration panel detected."),
        "api_surface": ("template_scan", 4, "Active API surface found, checking for vulnerabilities."),
        "role:dev": ("service_discovery", 3, "Development environment detected, mapping internal services."),
        "db_exposed": ("template_scan", 5, "Potential database interface exposed."),
        "login_page": ("template_scan", 3, "Auth surface found, checking for weak configurations."),
        "outdated_tech": ("template_scan", 4, "Legacy technology detected, running specific CVE checks."),
        "leaked_data_surface": ("template_scan", 5, "Exposed sensitive files or backup patterns detected.")
    }

    def evaluate_assets(self, assets: List[Dict[str, Any]]) -> List[TacticalAction]:
        """
        Evaluates a list of assets and returns recommended tactical actions.
        """
        actions = []
        seen_targets = set()

        for asset in assets:
            domain = asset.get("domain")
            labels = asset.get("semantic_labels", []) or []
            
            for label in labels:
                if label in self.STRATEGY_MAP:
                    capability, priority, reason = self.STRATEGY_MAP[label]
                    
                    # Avoid duplicate actions for the same target and capability
                    action_key = f"{domain}:{capability}"
                    if action_key not in seen_targets:
                        actions.append(TacticalAction(
                            capability=capability,
                            target=domain,
                            reason=reason,
                            priority=priority,
                            params={"labels": [label]}
                        ))
                        seen_targets.add(action_key)
        
        # Sort by priority
        actions.sort(key=lambda x: x.priority, reverse=True)
        return actions

# Global Instance
autonomy_engine = AutonomyEngine()
