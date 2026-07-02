"""
PromptWall Priority Engine - Inteligencia Adaptativa
Calcula la prioridad de los objetivos basándose en memoria histórica y señales de ataque.
"""

from typing import List, Dict, Any, Optional
from src.core.logging import get_logger
from src.storage.queries import DBQueries

logger = get_logger('priority_engine')

class PriorityEngine:
    """Motor de prioridad que aprende de sesiones pasadas."""
    
    def __init__(self, db_session):
        self.db = DBQueries(db_session)
        
    def score_hosts(self, target: str, hosts: List[str]) -> List[Dict[str, Any]]:
        """
        Calcula un score de prioridad para una lista de hosts.
        Retorna lista de dicts {host, score, reasons} ordenados por score.
        """
        scored_hosts = []
        
        # 1. Recuperar memoria del target
        host_reputation = self.db.get_agent_memory(target, "host_reputation")
        reputation_data = host_reputation.value if host_reputation else {}
        
        for host in hosts:
            score = 1.0  # Base
            reasons = []
            
            # A. Historial de Vulnerabilidades (Memoria)
            if host in reputation_data:
                rep = reputation_data[host]
                if rep.get('critical_count', 0) > 0:
                    score += 5.0
                    reasons.append("Historial de vulnerabilidades críticas")
                elif rep.get('high_count', 0) > 0:
                    score += 3.0
                    reasons.append("Historial de vulnerabilidades altas")
            
            # B. Señales Técnicas (de la DB)
            # Si el host tiene puertos interesantes (3000, 8080, etc.)
            # Nota: Esto asume que ya corrimos un service_discovery previo
            
            # C. Noveldad
            # Si es la primera vez que lo vemos, le damos un boost para investigar
            is_new = self.db.get_agent_memory(target, f"new_host:{host}")
            if is_new:
                score += 2.0
                reasons.append("Nuevo activo detectado - Alta prioridad de exploración")

            scored_hosts.append({
                "host": host,
                "score": round(score, 1),
                "reasons": reasons
            })
            
        # Ordenar por score descendente
        scored_hosts.sort(key=lambda x: x['score'], reverse=True)
        return scored_hosts

    def update_reputation(self, target: str, findings: List[Dict[str, Any]]):
        """Actualiza la memoria de reputación basada en nuevos hallazgos."""
        host_reputation = self.db.get_agent_memory(target, "host_reputation")
        data = host_reputation.value if host_reputation else {}
        
        for f in findings:
            host = f.get('host')
            if not host: continue
            
            if host not in data:
                data[host] = {'critical_count': 0, 'high_count': 0, 'total': 0}
            
            sev = f.get('severity', '').lower()
            if sev == 'critical': data[host]['critical_count'] += 1
            if sev == 'high': data[host]['high_count'] += 1
            data[host]['total'] += 1
            
        self.db.set_agent_memory(target, "host_reputation", data)
        logger.info(f"Updated host reputation memory for {target}")
