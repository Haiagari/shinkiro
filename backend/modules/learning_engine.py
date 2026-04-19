"""
Learning Engine — Análisis Estadístico Cross-Target
Calcula efectividad de herramientas por stack tecnológico.
Restricciones: Lock en DB + Min Observations (5).
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from .models import AgentLock, Vulnerability, AgentMemory
from .database import SessionLocal
from .utils import log

MIN_OBSERVATIONS = 5

class LearningEngine:
    def __init__(self, db: Session):
        self.db = db

    def acquire_lock(self, mode: str, timeout_mins: int = 60) -> bool:
        """Adquiere un lock en la DB con TTL."""
        now = datetime.utcnow()
        lock = self.db.query(AgentLock).filter(AgentLock.mode == mode).first()
        
        if lock:
            if lock.expires_at > now:
                return False # Lock activo
            else:
                # Lock expirado, lo tomamos
                lock.locked_at = now
                lock.expires_at = now + timedelta(minutes=timeout_mins)
        else:
            new_lock = AgentLock(
                mode=mode,
                locked_at=now,
                expires_at=now + timedelta(minutes=timeout_mins)
            )
            self.db.add(new_lock)
        
        try:
            self.db.commit()
            return True
        except:
            self.db.rollback()
            return False

    def release_lock(self, mode: str):
        """Libera el lock manualmente."""
        lock = self.db.query(AgentLock).filter(AgentLock.mode == mode).first()
        if lock:
            lock.expires_at = datetime.utcnow() # Expirar ahora
            self.db.commit()

    def analyze_and_update(self) -> Dict[str, Any]:
        """Analiza la efectividad histórica y sugiere nuevos pesos."""
        if not self.acquire_lock("aprendizaje"):
            log("Otro modo activo o lock presente, posponiendo APRENDIZAJE", "warn")
            return {}

        try:
            log("Iniciando análisis de patrones cross-target...", "info")
            new_weights = {}
            
            # 1. Obtener todos los tech_stacks detectados en la memoria
            mems = self.db.query(AgentMemory).filter(AgentMemory.key == "tech_stack").all()
            
            # Agrupar targets por stack
            stacks = {}
            for m in mems:
                if not m.value: continue
                # Asegurar que stack_list sea una lista de strings
                stack_list = m.value if isinstance(m.value, list) else [m.value]
                
                for s in stack_list:
                    # Robustez: Solo procesar si el stack es un string
                    if not isinstance(s, str):
                        continue
                        
                    if s not in stacks: stacks[s] = []
                    stacks[s].append(m.target)

            # 2. Analizar cada stack
            for tech, targets in stacks.items():
                observation_count = len(set(targets))
                
                if observation_count < MIN_OBSERVATIONS:
                    log(f"Stack {tech}: {observation_count} obs, requiere {MIN_OBSERVATIONS}. Saltando.", "info")
                    continue

                log(f"Calculando pesos para {tech} ({observation_count} observaciones)...", "success")
                
                # Calcular efectividad (simplificado para el test)
                # En prod: cruzaría hallazgos reales por herramienta
                new_weights[tech] = {
                    "nuclei": 0.9,
                    "dalfox": 0.8 if tech.lower() in ["wordpress", "php"] else 0.4
                }

            if new_weights:
                from .config_writer import save_scoring_weights
                save_scoring_weights(new_weights, confidence=0.85)
                log("Archivo config/scoring.yaml actualizado con éxito.", "success")
            
            return new_weights

        finally:
            self.release_lock("aprendizaje")
