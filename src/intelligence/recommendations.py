"""
Architecture Recommendation Engine - Consejos estratégicos basados en contexto v5.4
"""

from typing import List, Dict, Any

def generate_arch_recommendations(target: str, context: dict) -> List[Dict[str, str]]:
    """
    Analiza el contexto de la superficie y genera recomendaciones tácticas.
    """
    recommendations = []
    
    recon = context.get("phases", {}).get("recon", {})
    ports = context.get("phases", {}).get("ports", {})
    
    # Análisis de nombres y puertos
    open_ports = ports.get("open_ports", [])
    
    # 1. Aislamiento de DBs
    db_containers = [p for p in open_ports if (hasattr(p, 'port') and p.port in [5432, 6379, 3306])]
    if db_containers:
        recommendations.append({
            "title": "Network Isolation for Data Services",
            "description": "Critical data services (Postgres/Redis) are exposed on the network bridge. These should be moved to an internal-only network with no host port binding.",
            "priority": "HIGH"
        })

    # 2. Protección de Paneles
    auth_panels = [p for p in open_ports if (hasattr(p, 'port') and p.port in [5678, 8080])]
    if auth_panels:
        recommendations.append({
            "title": "Zero Trust Access for Admin Panels",
            "description": "Automation and Admin panels detected. Implementation of a VPN, Zero Trust Proxy (Cloudflare Access/Tailscale) or mTLS is recommended.",
            "priority": "MEDIUM"
        })

    # 3. Surface Reduction
    if len(open_ports) > 10:
        recommendations.append({
            "title": "Attack Surface Reduction",
            "description": "Large number of open ports detected on a single host. Review unnecessary services to minimize the attack surface.",
            "priority": "LOW"
        })

    return recommendations
