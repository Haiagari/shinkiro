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
        Builds a relationship graph with Smart Truncation (v8.3.1).
        Prioritizes high-risk nodes when over limit.
        """
        nodes = []
        edges = []
        seen_nodes = set()
        MAX_NODES = 500
        is_truncated = False

        scan = db.query(Scan).get(scan_id)
        if not scan:
            return {"nodes": [], "edges": []}

        # 1. Root Node (Target)
        target_label = scan.target.domain if scan.target else "Target"
        target_node_id = f"target_{scan.target_id}"
        self._add_node(nodes, seen_nodes, target_node_id, target_label, "target")

        # 2. Subdomains & IPs
        subdomains = db.query(Subdomain).filter_by(scan_id=scan_id).all()
        if len(subdomains) > MAX_NODES:
            subdomains = sorted(subdomains, key=lambda x: self._calculate_priority("subdomain", {"impact": x.business_impact}), reverse=True)[:MAX_NODES]
            is_truncated = True

        for sub in subdomains:
            # ...
            if len(nodes) >= MAX_NODES: break # Hard Stop
            sub_id = f"sub_{sub.id}"
            self._add_node(nodes, seen_nodes, sub_id, sub.domain, "subdomain", {
                "impact": sub.business_impact,
                "labels": sub.semantic_labels,
                "trace": sub.inference_trace # v7.5 - Explainability
            })
            self._add_edge(edges, target_node_id, sub_id, "has_subdomain")

            if sub.ip:
                ip_id = f"ip_{sub.ip}"
                self._add_node(nodes, seen_nodes, ip_id, sub.ip, "ip_address", {
                    "asn": sub.asn,
                    "org": sub.asn_organization
                })
                self._add_edge(edges, sub_id, ip_id, "resolves_to")

            # 2.5. DNS Chain / CNAME (v7.3)
            if sub.cname:
                cname_id = f"cname_{sub.cname}"
                self._add_node(nodes, seen_nodes, cname_id, sub.cname, "dns_cname")
                self._add_edge(edges, sub_id, cname_id, "cname_pointer")

        # 3. Ports & Services
        ports = db.query(Port).filter_by(scan_id=scan_id).all()
        for p in ports:
            # Find parent subdomain node (v8.3.2 fix: access through ['data']['label'])
            parent_id = next((n["data"]["id"] for n in nodes if n["data"]["label"] == p.host), None)
            
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
            
            # Link to port or subdomain (v8.3.2 fix: access through ['data']['label'])
            parent_id = next((n["data"]["id"] for n in nodes if n["data"]["label"] == v.host), None)
            if parent_id:
                self._add_edge(edges, parent_id, vuln_id, "vulnerable")

        # v8.3.2 - Extended Metadata for Operation
        return {
            "nodes": nodes, 
            "edges": edges, 
            "is_truncated": is_truncated,
            "metadata": {
                "total_nodes_detected": len(db.query(Subdomain).filter_by(scan_id=scan_id).all()),
                "nodes_returned": len(nodes),
                "schema_version": "1.2"
            }
        }

    def _add_node(self, nodes: List[Dict], seen: Set, id: str, label: str, type: str, metadata: Dict = None):
        if id not in seen:
            # v7.5 - Decision Guidance: Calculate visual priority
            priority = self._calculate_priority(type, metadata or {})
            
            # Wrap in 'data' for Cytoscape.js and legacy compatibility
            nodes.append({
                "data": {
                    "id": id,
                    "label": label,
                    "type": type,
                    "priority": priority,
                    "is_critical": priority >= 80,
                    "metadata": metadata or {}
                }
            })
            seen.add(id)

    def _calculate_priority(self, type: str, metadata: Dict) -> int:
        """Calculates a visual priority score (0-100) to guide the user."""
        if type == "finding":
            sev = str(metadata.get("severity", "info")).lower()
            return {"critical": 100, "high": 80, "medium": 50, "low": 20}.get(sev, 10)
        
        if type == "subdomain":
            impact = str(metadata.get("impact", "low")).upper()
            base = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 10}.get(impact, 0)
            # Boost if has sensitive labels
            labels = metadata.get("labels", []) or []
            if any(l in ["gate_admin", "api_surface"] for l in labels):
                base += 10
            return min(100, base)
            
        if type == "service":
            return metadata.get("criticality", 0)
            
        return 0

    def _add_edge(self, edges: List[Dict], source: str, target: str, relation: str):
        # Wrap in 'data' for Cytoscape.js and legacy compatibility
        edges.append({
            "data": {
                "source": source,
                "target": target,
                "relation": relation
            }
        })

# Global Instance
graph_builder = GraphBuilder()
