"""
Novelty Alerter Engine (OzyRecon v7 - Phase 3)
Detects and prioritizes significant changes in the attack surface.
"""

import logging
from typing import Dict, Any, List
from src.storage.diff import DiffReport

logger = logging.getLogger(__name__)

class NoveltyAlerter:
    """
    Analyzes differences between scans and classifies them by operational impact.
    """

    # Priority Levels
    CRITICAL = "CRITICAL" # New port, new subdomain in prod
    HIGH = "HIGH"         # Technology change, IP move outside cloud
    INFO = "INFO"         # Title change, minor tech update

    def __init__(self):
        self.alerts = []

    def analyze_diff(self, diff: DiffReport) -> List[Dict[str, Any]]:
        """
        Classifies changes in a DiffReport into operational alerts.
        """
        alerts = []

        # 1. Alert on New Subdomains
        for sub in diff.new_subdomains:
            alerts.append({
                "type": "NEW_ASSET",
                "priority": self.HIGH,
                "message": f"New subdomain discovered: {sub}",
                "entity": sub
            })

        # 2. Alert on New Ports
        for port in diff.new_ports:
            alerts.append({
                "type": "NEW_PORT",
                "priority": self.CRITICAL,
                "message": f"New open port detected: {port['host']}:{port['port']} ({port['service']})",
                "entity": f"{port['host']}:{port['port']}"
            })

        # 3. Alert on Technology Changes
        for change in diff.changed_subdomains:
            domain = change["domain"]
            metadata_changes = change["changes"]
            
            if "technologies" in metadata_changes:
                added = metadata_changes["technologies"]["added"]
                if added:
                    alerts.append({
                        "type": "TECH_CHANGE",
                        "priority": self.HIGH,
                        "message": f"New technologies detected on {domain}: {', '.join(added)}",
                        "entity": domain
                    })

            if "ip" in metadata_changes:
                alerts.append({
                    "type": "IP_MOVE",
                    "priority": self.INFO,
                    "message": f"Asset {domain} moved from {metadata_changes['ip']['old']} to {metadata_changes['ip']['new']}",
                    "entity": domain
                })

        self.alerts = alerts
        return alerts

    def get_summary(self) -> str:
        if not self.alerts:
            return "No significant novelties detected."
        
        critical_count = len([a for p in self.alerts if p['priority'] == self.CRITICAL])
        return f"Novelty detection found {len(self.alerts)} events ({critical_count} critical)."

# Global Instance
novelty_alerter = NoveltyAlerter()
