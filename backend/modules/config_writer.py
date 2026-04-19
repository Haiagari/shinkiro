"""
Config Writer — Escritura Segura de Pesos (Scoring)
Escribe SOLO a config/scoring.yaml, manteniendo config/config.yaml intacto.
"""

import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

ROOT_DIR = Path(__file__).resolve().parents[2]
SCORING_FILE = ROOT_DIR / "config" / "scoring.yaml"

def save_scoring_weights(weights: Dict[str, Any], confidence: float):
    """Guarda los pesos calculados por el modo APRENDIZAJE."""
    data = {
        "generated_at": datetime.now().isoformat(),
        "generated_by": "aprendizaje_mode",
        "confidence": confidence,
        "weights": weights
    }
    
    # Escribir a archivo temporal y luego renombrar (atomic-ish)
    tmp_file = SCORING_FILE.with_suffix(".tmp")
    with open(tmp_file, "w") as f:
        yaml.dump(data, f, default_flow_style=False)
    
    tmp_file.replace(SCORING_FILE)

def load_effective_weights(base_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Carga pesos con prioridad: 
    1. config/scoring.yaml (si existe)
    2. config/config.yaml (defaults)
    """
    if SCORING_FILE.exists():
        try:
            with open(SCORING_FILE, "r") as f:
                learned_data = yaml.safe_load(f)
                return learned_data.get("weights", base_config.get("scoring", {}))
        except:
            pass
    
    return base_config.get("scoring", {})
