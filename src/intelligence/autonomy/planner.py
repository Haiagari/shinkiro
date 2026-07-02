"""
Adaptive Recon Planner (PromptWall v7 - Phase 8)
Decides the best execution profile based on the target type and operational intent.
"""

import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ReconPlanner:
    """
    Analyzes targets to generate optimized execution plans.
    """

    def generate_plan(self, target: str, intent: str = "balanced") -> Dict[str, Any]:
        """
        Generates an execution plan based on target characteristics.
        """
        target_type = self._detect_target_type(target)
        
        plan = {
            "target": target,
            "type": target_type,
            "intent": intent,
            "capabilities": [],
            "options": {
                "threads": 10,
                "timeout": 10,
                "speed": "normal"
            }
        }

        # 1. Base Capabilities by Target Type
        if target_type == "domain":
            plan["capabilities"] = ["asset_discovery", "dns_resolution", "live_detection"]
            if intent in ["balanced", "aggressive"]:
                plan["capabilities"].extend(["service_discovery", "port_scan"])
        
        elif target_type == "ip":
            plan["capabilities"] = ["live_detection", "service_discovery", "port_scan"]
            plan["options"]["threads"] = 5 # IPs are usually single hosts

        # 2. Adjust by Intent
        if intent == "stealth":
            plan["options"]["threads"] = 2
            plan["options"]["speed"] = "slow"
            # Remove noise-heavy tools if we had a blacklist here
            if "port_scan" in plan["capabilities"]:
                plan["capabilities"].remove("port_scan")
        
        elif intent == "aggressive":
            plan["options"]["threads"] = 50
            plan["options"]["speed"] = "fast"
            plan["capabilities"].append("template_scan")

        return plan

    def _detect_target_type(self, target: str) -> str:
        """
        Identifies if target is a domain, IP, or CIDR.
        """
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", target):
            return "ip"
        if "/" in target:
            return "cidr"
        return "domain"

# Global Instance
recon_planner = ReconPlanner()
