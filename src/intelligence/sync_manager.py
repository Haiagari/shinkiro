"""
SyncManager - Gestión de Sincronización de Inteligencia
Permite exportar e importar el "cerebro" de OzyRecon entre instancias.
"""

import json
import zipfile
from pathlib import Path
from datetime import datetime
from src.core.logging import get_logger
from src.intelligence.feedback_engine import feedback_engine
from src.intelligence.false_positive_memory import false_positive_memory

logger = get_logger('sync_manager')

class SyncManager:
    """Gestiona la exportación/importación del estado mental del sistema."""
    
    def __init__(self):
        self.config_dir = Path("runtime/config")
        self.export_dir = Path("runtime/exports/sync")
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def export_brain(self) -> Path:
        """Empaqueta pesos y falsos positivos en un archivo transferible."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = self.export_dir / f"brain_sync_{timestamp}.ozy"
        
        data = {
            "weights": feedback_engine.get_adjusted_weights(),
            "false_positives": [p.to_dict() for p in false_positive_memory.patterns.values()],
            "exported_at": datetime.now().isoformat(),
            "version": "4.0"
        }
        
        with open(export_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Brain exported to {export_file}")
        return export_file

    def import_brain(self, file_path: Path):
        """Importa y mezcla inteligencia de otra instancia."""
        if not file_path.exists():
            logger.error(f"Sync file not found: {file_path}")
            return False
            
        try:
            with open(file_path) as f:
                data = json.load(f)
            
            # 1. Mezclar Pesos (Promedio ponderado simple)
            current_weights = feedback_engine.weights
            incoming_weights = data.get("weights", {})
            
            for key in incoming_weights:
                if hasattr(current_weights, key):
                    # El aprendizaje colectivo es un promedio de las experiencias
                    new_val = (getattr(current_weights, key) + incoming_weights[key]) / 2
                    setattr(current_weights, key, new_val)
            
            feedback_engine._save_weights()
            
            # 2. Mezclar Falsos Positivos
            incoming_fps = data.get("false_positives", [])
            for fp in incoming_fps:
                false_positive_memory.register_false_positive(
                    fp["pattern_type"], 
                    fp["pattern_value"], 
                    fp["tool"]
                )
            
            logger.info(f"Successfully imported intelligence from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import brain: {e}")
            return False

# Instancia global
sync_manager = SyncManager()
