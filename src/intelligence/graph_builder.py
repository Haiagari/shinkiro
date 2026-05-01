"""
Knowledge Graph Builder (OzyRecon v7 - Phase 10)
Assembles a relationship model of the target surface.
"""

import logging
from typing import Dict, Any, List, Set
from sqlalchemy.orm import Session
from src.storage.models import Target, Scan, Subdomain, Port, Vulnerability

logger = logging.getLogger(__name__)

class GraphBuilder:
    """
    Transforms database records into a graph structure (Nodes & Edges).
    """

    def build_scan_graph(self, db: Session, scan_id: int) -> Dict[str, Any]:
        """
        Builds a relationship graph for a specific scan.
        """
        nodes = []
        edges = []
        seen_nodes = set()

        scan = db.query(Scan).get(scan_id)
        if not scan:
            return {"nodes": [], "edges": []}

        # 1. Root Node (Target)
        target_label = scan.target.domain if scan.target else "Target"
        target_node_id = f"target_{scan.target_id}"
        self._add_node(nodes, seen_nodes, target_node_id, target_label, "target")

        # 2. Subdomains & IPs
        subdomains = db.query(Subdomain).filter_by(scan_id=scan_id).all()
        for sub in subdomains:
            sub_id = f"sub_{sub.id}"
            self._add_node(nodes, seen_nodes, sub_id, sub.domain, "subdomain", {
                "impact": sub.business_impact,
                "labels": sub.semantic_labels
            })
            self._add_edge(edges, target_node_id, sub_id, "has_subdomain")

            if sub.ip:
                ip_id = f"ip_{sub.ip}"
                self._add_node(nodes, seen_nodes, ip_id, sub.ip, "ip_address", {
                    "asn": sub.asn,
                    "org": sub.asn_organization
                })
                self._add_edge(edges, sub_id, ip_id, "resolves_to")

        # 3. Ports & Services
        ports = db.query(Port).filter_by(scan_id=scan_id).all()
        for p in ports:
            # Find parent subdomain node (simple match by host string)
            parent_id = next((n["id"] for n in nodes if n["label"] == p.host), None)
            
            port_id = f"port_{p.id}"
            label = f"{p.port}/{p.protocol}"
            self._add_node(nodes, seen_nodes, port_id, label, "service", {
                "service": p.service,
                "version": p.version,
                "criticality": p.criticality_index
            })
            
            if parent_id:
                self._add_edge(edges, parent_id, port_id, "opens_port")

            # 4. Technologies
            if p.product:
                tech_id = f"tech_{p.product.lower()}"
                self._add_node(nodes, seen_nodes, tech_id, p.product, "technology")
                self._add_edge(edges, port_id, tech_id, "runs")

        # 5. Vulnerabilities (Findings)
        vulns = db.query(Vulnerability).filter_by(scan_id=scan_id).all()
        for v in vulns:
            vuln_id = f"vuln_{v.id}"
            self._add_node(nodes, seen_nodes, vuln_id, v.name, "finding", {
                "severity": v.severity,
                "cvss": v.cvss
            })
            
            # Link to port or subdomain
            parent_id = next((n["id"] for n in nodes if n["label"] == v.host), None)
            if parent_id:
                self._add_edge(edges, parent_id, vuln_id, "vulnerable")

        return {"nodes": nodes, "edges": edges}

    def _add_node(self, nodes: List[Dict], seen: Set, id: str, label: str, type: str, metadata: Dict = None):
        if id not in seen:
            nodes.append({
                "id": id,
                "label": label,
                "type": type,
                "metadata": metadata or {}
            })
            seen.add(id)

    def _add_edge(self, edges: List[Dict], source: str, target: str, relation: str):
        edges.append({
            "source": source,
            "target": target,
            "relation": relation
        })

# Global Instance
graph_builder = GraphBuilder()
