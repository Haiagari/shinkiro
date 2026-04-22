"""
Evidence Engine - Trazabilidad y recolección de pruebas v5.0
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional
from src.storage.database import SessionLocal
from src.storage.models import Evidence, Hypothesis
from src.core.logging import get_logger

logger = get_logger('evidence_engine')

class EvidenceEngine:
    def __init__(self):
        pass

    def record_evidence(self, hypothesis_id: str, evidence_type: str, data: Any, metadata: Dict[str, Any] = None) -> Optional[str]:
        """
        Registra una pieza de evidencia vinculada a una hipótesis.
        """
        db = SessionLocal()
        try:
            # Generar ID único para la evidencia
            data_str = str(data)
            evidence_id = f"ev_{hashlib.md5((hypothesis_id + data_str + str(datetime.now())).encode()).hexdigest()[:8]}"
            
            # Calcular hash de integridad
            content_hash = hashlib.sha256(data_str.encode()).hexdigest()

            new_evidence = Evidence(
                id=evidence_id,
                hypothesis_id=hypothesis_id,
                type=evidence_type,
                data=data_str,
                metadata_json=metadata or {},
                hash_sha256=content_hash,
                timestamp=datetime.utcnow()
            )

            db.add(new_evidence)
            db.commit()
            logger.info(f"Evidence {evidence_id} recorded for hypothesis {hypothesis_id}")
            return evidence_id
        except Exception as e:
            db.rollback()
            logger.error(f"Error recording evidence: {str(e)}")
            return None
        finally:
            db.close()

    def get_evidence_for_hypothesis(self, hypothesis_id: str):
        """Recupera toda la evidencia asociada a una hipótesis."""
        db = SessionLocal()
        try:
            return db.query(Evidence).filter(Evidence.hypothesis_id == hypothesis_id).all()
        finally:
            db.close()

# Instancia global
evidence_engine = EvidenceEngine()
