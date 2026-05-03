"""
OzyRecon Graph Exporter (v8.3.2)
Generates standalone, interactive HTML reports based on the professional D3 template.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from src.core.logging import get_logger

logger = get_logger("reporting.graph")

class GraphExporter:
    def __init__(self, template_path: str = "src/core/static/index.html"):
        self.template_path = Path(template_path)

    def generate_standalone_report(self, data: Dict[str, Any], output_path: str):
        """
        Takes real scan data and injects it into the professional template 
        to create a portable HTML report.
        """
        if not self.template_path.exists():
            logger.error(f"Template not found at {self.template_path}")
            return

        # Prepare D3-compatible data
        d3_nodes = []
        for n in data.get("nodes", []):
            d3_nodes.append({
                "id": n["data"]["id"],
                "label": n["data"]["label"],
                "type": n["data"]["type"],
                "risk": "CRITICAL" if n["data"].get("is_critical") else "ACTIVE",
                "detail": str(n["data"].get("metadata", {}))
            })
        
        d3_edges = []
        for e in data.get("edges", []):
            d3_edges.append({
                "source": e["data"]["source"],
                "target": e["data"]["target"]
            })

        graph_json = json.dumps({"nodes": d3_nodes, "edges": d3_edges})
        
        # Read template
        content = self.template_path.read_text(encoding="utf-8")
        
        # Inject data (This assumes we have a placeholder or we replace the bridge logic)
        # For a standalone report, we replace the 'ozyFetch' bridge with static data.
        report_content = content.replace(
            "setTimeout(loadRealData, 1000);",
            f"const RAW_DATA = {graph_json}; initD3Graph(RAW_DATA.nodes, RAW_DATA.edges); updateStats(RAW_DATA.nodes, RAW_DATA.edges);"
        )
        
        Path(output_path).write_text(report_content, encoding="utf-8")
        logger.info(f"Standalone graph report generated: {output_path}")

graph_exporter = GraphExporter()
