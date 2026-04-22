"""
Base Validator - Interfaz para validación de hipótesis v5.0
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime
import uuid

class ValidationResult:
    def __init__(self, hypothesis_id: str, status: str, confidence: float, evidence: List[Dict[str, Any]] = None, notes: str = ""):
        self.hypothesis_id = hypothesis_id
        self.status = status # confirmed, refuted, inconclusive
        self.confidence_after = confidence
        self.evidence = evidence or []
        self.notes = notes
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "status": self.status,
            "confidence_after_validation": self.confidence_after,
            "evidence": self.evidence,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat()
        }

class BaseValidator(ABC):
    """
    Base Validator - Interfaz para validación de hipótesis v5.0.
    
    FILOSOFÍA DE DISEÑO:
    - NO EXPLOITATION: No se ejecutan payloads destructivos.
    - NO INTRUSION: No se busca acceso persistente.
    - CONTROLLED PROBING: Solo confirmación de exposición/misconfiguración.
    """
    @abstractmethod
    def validate(self, hypothesis: Dict[str, Any]) -> ValidationResult:
        pass

    def create_evidence(self, type: str, data: Any, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Helper para crear registros de evidencia consistentes."""
        return {
            "id": f"ev_{uuid.uuid4().hex[:8]}",
            "type": type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": str(data),
            "metadata": metadata or {}
        }
