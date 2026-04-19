"""
Modo FORENSE - Análisis Post-Mortem
Análisis de brechas de detección y auto-ajuste de scoring.
"""

import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

from src.core.config import config
from src.core.logging import get_logger
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries

logger = get_logger('mode_forensic')


class ForensicMode:
    """
    Modo FORENSE - Análisis Post-Mortem
    
    Objetivo: Analizar brechas de detección y ajustar scoring.
    
    Flujo:
    1. Analizar historial de scans
    2. Identificar patrones fallidos
    3. Detectar brechas en la detección
    4. Proponer ajustes de scoring
    """
    
    def __init__(self, target: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode="forensic"
        )
        set_context(self.context)
        
        self.db = None
    
    def run(self) -> Dict[str, Any]:
        """Ejecuta el análisis forense."""
        logger.info(f"[FORENSIC] Starting forensic analysis on {self.target}")
        self.context.mark_running()
        
        try:
            init_db()
            db_session = SessionLocal()
            self.db = DBQueries(db_session)
            
            # Analizar historial
            history = self._analyze_history()
            
            # Detectar patrones
            patterns = self._detect_patterns(history)
            
            # Identificar brechas
            gaps = self._identify_gaps(history, patterns)
            
            # Proponer ajustes
            recommendations = self._generate_recommendations(gaps)
            
            self.context.mark_completed()
            
            return {
                'session_id': self.session_id,
                'target': self.target,
                'history_analyzed': len(history),
                'patterns_found': len(patterns),
                'gaps_identified': len(gaps),
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.exception(f"[FORENSIC] Error: {e}")
            self.context.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}
    
    def _analyze_history(self) -> List[Dict[str, Any]]:
        """Analiza el historial de scans del target."""
        scans = self.db.get_scans_for_target(self.target, limit=30)
        
        history = []
        for scan in scans:
            history.append({
                'scan_id': scan.id,
                'timestamp': scan.start_time,
                'subdomains': scan.subdomains_found,
                'hosts': scan.hosts_alive,
                'ports': scan.ports_found,
                'findings': scan.findings,
                'status': scan.status
            })
        
        return history
    
    def _detect_patterns(self, history: List[Dict]) -> List[Dict[str, Any]]:
        """Detecta patrones en el historial."""
        patterns = []
        
        if not history:
            return patterns
        
        # Pattern: Disminución de hallazgos
        findings = [h['findings'] for h in history if h['findings']]
        if len(findings) >= 3:
            if findings[-1] < findings[0] * 0.5:
                patterns.append({
                    'type': 'declining_findings',
                    'description': 'Los hallazgos están disminuyendo consistentemente',
                    'severity': 'high'
                })
        
        # Pattern: Hosts sin hallazgos
        hosts_no_findings = [h for h in history if h['hosts'] > 0 and h['findings'] == 0]
        if len(hosts_no_findings) > len(history) * 0.5:
            patterns.append({
                'type': 'no_findings_on_hosts',
                'description': ' Muchos hosts sin hallazgos - posible limitación de scope',
                'severity': 'medium'
            })
        
        return patterns
    
    def _identify_gaps(self, history: List[Dict], patterns: List[Dict]) -> List[Dict[str, Any]]:
        """Identifica brechas en la detección."""
        gaps = []
        
        for pattern in patterns:
            if pattern['type'] == 'declining_findings':
                gaps.append({
                    'area': 'coverage',
                    'issue': 'Disminución de cobertura o cambios en el target',
                    'suggestion': 'Revisar scope y actualizar técnicas de descubrimiento'
                })
            elif pattern['type'] == 'no_findings_on_hosts':
                gaps.append({
                    'area': 'scanning',
                    'issue': 'Hosts detectados pero sin vulnerabilidades',
                    'suggestion': 'Añadir más templates de Nuclei o verificar falsos negativos'
                })
        
        return gaps
    
    def _generate_recommendations(self, gaps: List[Dict]) -> List[str]:
        """Genera recomendaciones basadas en las brechas."""
        recommendations = []
        
        for gap in gaps:
            recommendations.append(f"[{gap['area']}] {gap['suggestion']}")
        
        if not recommendations:
            recommendations.append("No se identificaron brechas significativas")
        
        return recommendations


def run_forensic(target: str, **options) -> Dict[str, Any]:
    """Función de conveniencia para modo Forensic."""
    mode = ForensicMode(target, options)
    return mode.run()