"""
FalsePositiveMemory - Memoria de Falsos Positivos
Fase 2: Aprendizaje Reflexivo
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
from pathlib import Path
from src.core.runtime_paths import get_config_dir

@dataclass
class FalsePositivePattern:
    """
    Patrón que genera falsos positivos.
    """
    id: str
    pattern_type: str        # "tool", "template", "parameter", "url_pattern"
    pattern_value: str
    tool: str
    frequency: int = 1
    first_seen: str = ""
    last_seen: str = ""
    
    @property
    def false_positive_rate(self) -> float:
        """Calcula tasa de FP basada en ocurrencias."""
        # Simple: más veces visto = más probable que sea FP
        return min(1.0, self.frequency / 10)
    
    @property
    def should_avoid(self) -> bool:
        """Si debe evitarse este patrón."""
        return self.frequency >= 3
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pattern_type": self.pattern_type,
            "pattern_value": self.pattern_value,
            "tool": self.tool,
            "frequency": self.frequency,
            "false_positive_rate": self.false_positive_rate,
            "should_avoid": self.should_avoid
        }

class FalsePositiveMemory:
    """
    Mantiene registro de patrones que generan falsos positivos.
    """
    
    # Threshold para considerar un patrón como problemático
    FP_THRESHOLD = 3
    
    def __init__(self, db_session=None):
        self.db = db_session
        self.local_storage = get_config_dir() / "false_positives.json"
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, FalsePositivePattern]:
        """Carga patrones desde archivo local."""
        if self.local_storage.exists():
            with open(self.local_storage) as f:
                data = json.load(f)
                return {
                    k: FalsePositivePattern(**v) 
                    for k, v in data.items()
                }
        return {}
    
    def _save_patterns(self):
        """Guarda patrones actualizados."""
        self.local_storage.parent.mkdir(parents=True, exist_ok=True)
        with open(self.local_storage, 'w') as f:
            json.dump(
                {k: v.to_dict() for k, v in self.patterns.items()}, 
                f, indent=2
            )
    
    def register_false_positive(
        self,
        pattern_type: str,
        pattern_value: str,
        tool: str,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Registra un nuevo falso positivo.
        """
        import uuid
        
        # Crear ID único
        pattern_id = f"{pattern_type}:{pattern_value}:{tool}"
        
        if pattern_id in self.patterns:
            # Incrementar frecuencia
            self.patterns[pattern_id].frequency += 1
            self.patterns[pattern_id].last_seen = datetime.utcnow().isoformat()
        else:
            # Nuevo patrón
            self.patterns[pattern_id] = FalsePositivePattern(
                id=pattern_id,
                pattern_type=pattern_type,
                pattern_value=pattern_value,
                tool=tool,
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat()
            )
        
        self._save_patterns()
    
    def register_discovery(
        self,
        finding_id: str,
        tool: str,
        finding_details: Dict[str, Any]
    ):
        """
        Registra un finding como falso positivo (descartado por usuario).
        """
        # Determinar tipo de patrón
        pattern_type = "template"
        if "template" in finding_details:
            pattern_value = finding_details["template"]
        elif "url" in finding_details:
            # Extraer patrón de URL
            url = finding_details["url"]
            pattern_value = url.split("?")[0]  # Sin parámetros
        elif "parameter" in finding_details:
            pattern_type = "parameter"
            pattern_value = finding_details["parameter"]
        else:
            pattern_type = "finding"
            pattern_value = finding_id
        
        self.register_false_positive(pattern_type, pattern_value, tool)
    
    def should_skip(
        self,
        pattern_type: str,
        pattern_value: str,
        tool: str
    ) -> bool:
        """
        Determina si debe saltar un patrón.
        """
        pattern_id = f"{pattern_type}:{pattern_value}:{tool}"
        
        if pattern_id in self.patterns:
            return self.patterns[pattern_id].should_avoid
        
        return False
    
    def get_avoid_list(self, tool: str = None) -> List[str]:
        """
        Retorna lista de patrones a evitar.
        """
        avoid = []
        for pattern in self.patterns.values():
            if pattern.should_avoid:
                if tool is None or pattern.tool == tool:
                    avoid.append(pattern.pattern_value)
        return avoid
    
    def get_tool_statistics(self, tool: str) -> Dict[str, Any]:
        """
        Obtiene estadísticas de FP por herramienta.
        """
        tool_patterns = [p for p in self.patterns.values() if p.tool == tool]
        
        if not tool_patterns:
            return {"total": 0, "avoid": 0}
        
        return {
            "total": len(tool_patterns),
            "avoid": sum(1 for p in tool_patterns if p.should_avoid),
            "avg_frequency": sum(p.frequency for p in tool_patterns) / len(tool_patterns),
            "false_positive_rate": sum(p.false_positive_rate for p in tool_patterns) / len(tool_patterns)
        }
    
    def cleanup_old_entries(self, days: int = 30):
        """
        Limpia entradas antiguas (no vistas en X días).
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        to_remove = []
        
        for pid, pattern in self.patterns.items():
            if pattern.last_seen:
                last = datetime.fromisoformat(pattern.last_seen)
                if last < cutoff:
                    to_remove.append(pid)
        
        for pid in to_remove:
            del self.patterns[pid]
        
        if to_remove:
            self._save_patterns()

# Instancia global
false_positive_memory = FalsePositiveMemory()
