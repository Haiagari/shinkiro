"""
DecisionLog - Registro de Decisiones
Fase 2: Aprendizaje Reflexivo
"""

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, Optional, List
from src.storage.database import SessionLocal
from src.storage.models import Base
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from src.utils import get_logger

logger = get_logger('decision_log')

class DecisionType:
    PRIORITIZE_HOST = "prioritize_host"
    TRIGGER_SCAN = "trigger_scan"
    SKIP_SCAN = "skip_scan"
    ADAPT_OPSEC = "adapt_opsec"
    ADJUST_SCORING = "adjust_scoring"
    FILTER_TEMPLATE = "filter_template"

@dataclass
class Decision:
    """
    Representa una decisión tomada por el sistema.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    decision_type: str = ""
    target: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    #-weight info (before decision)
    reputation_weight: float = 0.5
    novelty_weight: float = 0.3
    diff_weight: float = 0.2
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class DecisionRepository:
    """Repositorio para persistir decisiones."""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def save(self, decision: Decision) -> Decision:
        """Guarda una decisión en la DB."""
        from src.storage.models import Decision as DecisionModel
        
        # Create table if not exists
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS decisions ("
            "id TEXT PRIMARY KEY, session_id TEXT, decision_type TEXT, "
            "target TEXT, context JSON, reason TEXT, timestamp TEXT, "
            "reputation_weight REAL, novelty_weight REAL, diff_weight REAL)"
        )
        
        self.db.execute(
            """INSERT OR REPLACE INTO decisions 
            (id, session_id, decision_type, target, context, reason, timestamp, 
             reputation_weight, novelty_weight, diff_weight)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision.id,
                decision.session_id,
                decision.decision_type,
                decision.target,
                str(decision.context),  # JSON string
                decision.reason,
                decision.timestamp,
                decision.reputation_weight,
                decision.novelty_weight,
                decision.diff_weight
            )
        )
        self.db.commit()
        logger.info(f"Decision logged: {decision.decision_type} for {decision.target}")
        return decision
    
    def get_by_session(self, session_id: str) -> List[Decision]:
        """Obtiene todas las decisiones de una sesión."""
        from src.storage.models import Decision as DecisionModel
        
        result = self.db.execute(
            "SELECT * FROM decisions WHERE session_id = ? ORDER BY timestamp",
            (session_id,)
        ).fetchall()
        
        decisions = []
        for row in result:
            decisions.append(Decision(
                id=row[0],
                session_id=row[1],
                decision_type=row[2],
                target=row[3],
                context=eval(row[4]) if row[4] else {},
                reason=row[5],
                timestamp=row[6],
                reputation_weight=row[7],
                novelty_weight=row[8],
                diff_weight=row[9]
            ))
        return decisions
    
    def get_recent(self, limit: int = 50) -> List[Decision]:
        """Obtiene las últimas N decisiones."""
        result = self.db.execute(
            f"SELECT * FROM decisions ORDER BY timestamp DESC LIMIT {limit}"
        ).fetchall()
        
        decisions = []
        for row in result:
            decisions.append(Decision(
                id=row[0],
                session_id=row[1],
                decision_type=row[2],
                target=row[3],
                context=eval(row[4]) if row[4] else {},
                reason=row[5],
                timestamp=row[6],
                reputation_weight=row[7],
                novelty_weight=row[8],
                diff_weight=row[9]
            ))
        return decisions

    def get_average_weights(self) -> Dict[str, float]:
        """Calcula el promedio de pesos usados."""
        result = self.db.execute(
            "SELECT AVG(reputation_weight), AVG(novelty_weight), AVG(diff_weight) FROM decisions"
        ).fetchone()
        
        return {
            "reputation": result[0] or 0.5,
            "novelty": result[1] or 0.3,
            "diff": result[2] or 0.2
        }


def log_decision(
    session_id: str,
    decision_type: str,
    target: str,
    reason: str,
    context: Dict[str, Any],
    weights: Optional[Dict[str, float]] = None
) -> Decision:
    """Función helper para registrar una decisión."""
    db = SessionLocal()
    try:
        repo = DecisionRepository(db)
        decision = Decision(
            session_id=session_id,
            decision_type=decision_type,
            target=target,
            reason=reason,
            context=context,
            reputation_weight=weights.get("reputation", 0.5) if weights else 0.5,
            novelty_weight=weights.get("novelty", 0.3) if weights else 0.3,
            diff_weight=weights.get("diff", 0.2) if weights else 0.2
        )
        return repo.save(decision)
    finally:
        db.close()