"""
FeedbackEngine - Ajuste de Scoring
Fase 2: Aprendizaje Reflexivo
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import json
from pathlib import Path

from src.core.logging import get_logger
from src.core.runtime_paths import get_config_dir

logger = get_logger('feedback_engine')

@dataclass
class ScoringWeights:
    """
    Pesos actuales del sistema.
    """
    reputation: float = 0.5
    novelty: float = 0.3
    diff_signal: float = 0.2
    
    # Ajustes por modo
    hunt_aggression: float = 1.0
    continuous_aggression: float = 0.5
    research_depth: float = 1.0
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "reputation": self.reputation,
            "novelty": self.novelty,
            "diff_signal": self.diff_signal,
            "hunt_aggression": self.hunt_aggression,
            "continuous_aggression": self.continuous_aggression,
            "research_depth": self.research_depth
        }

class FeedbackEngine:
    """
    Ajusta el sistema en base a resultados reales.
    """
    
    # Tasas de aprendizaje
    LEARNING_RATE = 0.1       # Cuánto ajustar por defecto
    FAST_LEARNING = 0.2     # Cuánto ajustar cuando hay certeza
    SLOW_LEARNING = 0.05     # Cuánto ajustar cuando hay incertidumbre
    
    # Rangos válidos
    MIN_WEIGHT = 0.1
    MAX_WEIGHT = 0.9
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or get_config_dir() / "scoring_weights.json"
        self.weights = self._load_weights()
    
    def _load_weights(self) -> ScoringWeights:
        """Carga pesos desde archivo o usa defaults."""
        if self.config_path.exists():
            with open(self.config_path) as f:
                data = json.load(f)
                return ScoringWeights(**data)
        return ScoringWeights()
    
    def _save_weights(self):
        """Guarda pesos actualizados."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.weights.to_dict(), f, indent=2)
    
    def adjust_on_success(
        self,
        decision_type: str,
        improvement_factor: float = 1.0
    ):
        """
        Ajusta pesos cuando una decisión fue exitosa.
        """
        rate = self.LEARNING_RATE * improvement_factor
        
        if decision_type == "prioritize_host":
            # Si priorizar hosts funcionó, aumentar peso de reputación
            self.weights.reputation = min(
                self.MAX_WEIGHT,
                self.weights.reputation + rate
            )
        elif decision_type == "trigger_scan_on_diff":
            # Si escanear lo nuevo funcionó, aumentar peso de diff
            self.weights.diff_signal = min(
                self.MAX_WEIGHT,
                self.weights.diff_signal + rate
            )
        
        self._save_weights()
    
    def adjust_on_failure(
        self,
        decision_type: str,
        improvement_factor: float = 1.0
    ):
        """
        Ajusta pesos cuando una decisión fallo.
        """
        rate = self.LEARNING_RATE * improvement_factor
        
        if decision_type == "prioritize_host":
            # Si priorizar hosts no funcionó, reducir peso
            self.weights.reputation = max(
                self.MIN_WEIGHT,
                self.weights.reputation - rate
            )
            # Aumentar peso de novelty
            self.weights.novelty = min(
                self.MAX_WEIGHT,
                self.weights.novelty + rate
            )
        elif decision_type == "trigger_scan_on_diff":
            # Si escanear lo nuevo no funcionó, reducir peso
            self.weights.diff_signal = max(
                self.MIN_WEIGHT,
                self.weights.diff_signal - rate
            )
        
        self._save_weights()
    
    def adjust_from_outcome(
        self,
        decision_type: str,
        was_successful: bool,
        confidence: float = 1.0
    ):
        """
        Ajusta basado en outcome directo con logs de aprendizaje.
        """
        rate = (
            self.FAST_LEARNING if confidence > 0.8 
            else self.SLOW_LEARNING
        )
        
        logger.info(f"Learning from {decision_type}: success={was_successful}, confidence={confidence:.2f}")
        
        if was_successful:
            self.adjust_on_success(decision_type, rate)
        else:
            self.adjust_on_failure(decision_type, rate)
    
    def get_adjusted_weights(self) -> Dict[str, float]:
        """Retorna los pesos actuales."""
        return self.weights.to_dict()
    
    def get_insights(self) -> Dict[str, Any]:
        """Genera insights sobre el comportamiento del sistema."""
        return {
            "current_weights": self.weights.to_dict(),
            "insights": [
                f"Peso de reputación: {self.weights.reputation:.0%}",
                f"Peso de novedad: {self.weights.novelty:.0%}",
                f"Señal de cambio: {self.weights.diff_signal:.0%}",
            ],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> list:
        """Genera recomendaciones basadas en pesos actuales."""
        recs = []
        
        if self.weights.reputation > 0.7:
            recs.append("Sistema prioriza fuertemente hosts con historial")
        elif self.weights.reputation < 0.3:
            recs.append("Sistema prioriza hosts nuevos sobre históricos")
        
        if self.weights.diff_signal > 0.5:
            recs.append("Sistema sensible a cambios en superficie")
        
        if self.weights.novelty > 0.5:
            recs.append("Sistema prioriza assets nuevos")
        
        return recs
    
    def reset_to_defaults(self):
        """Resetea todos los pesos a valores por defecto."""
        self.weights = ScoringWeights()
        self._save_weights()

# Instancia global
feedback_engine = FeedbackEngine()
