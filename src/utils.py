"""
Utilidades Compartidas de OzyRecon
Funciones helper para todo el proyecto.
"""

import subprocess
import logging
import json
import yaml
from pathlib import Path
from typing import List, Any, Dict

# Logger
def get_logger(name: str) -> logging.Logger:
    """Obtiene un logger configurado."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)s | %(message)s')
        )
        logger.addHandler(handler)
    return logger

_logger = get_logger('ozyrecon')
logger = _logger

def log(message: str, level: str = "info"):
    """Función helper para loguear con estilo."""
    levels = {
        "info": _logger.info,
        "success": _logger.info,
        "warn": _logger.warning,
        "error": _logger.error,
        "critical": _logger.critical,
        "debug": _logger.debug
    }
    log_func = levels.get(level.lower(), _logger.info)
    
    # Agregar prefijos visuales si es éxito o alerta
    if level == "success":
        message = f"✅ {message}"
    elif level == "warn":
        message = f"⚠️ {message}"
    elif level == "error":
        message = f"❌ {message}"
        
    log_func(message)


def load_config() -> Dict:
    """Carga configuración desde config.yaml"""
    config_path = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_json(path: Path, data: Any):
    """Guarda JSON a archivo."""
    if isinstance(path, str):
        path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: Path) -> Any:
    """Carga JSON desde archivo."""
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def run_cmd(cmd: List[str], timeout: int = 30, capture: bool = True) -> subprocess.CompletedProcess:
    """Ejecuta un comando shell."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            cwd=Path(__file__).resolve().parents[2]
        )
        return result
    except subprocess.TimeoutExpired:
        log.error(f"Timeout executing: {' '.join(cmd)}")
        raise


def read_lines(path: Path) -> List[str]:
    """Lee líneas de un archivo."""
    if path.exists():
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    return []


def write_lines(lines: List[str], path: Path):
    """Escribe líneas a archivo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def dedupe(items: List[Any]) -> List[Any]:
    """Elimina duplicados manteniendo orden."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def check_tools(tools: List[str]) -> Dict[str, bool]:
    """Verifica si las herramientas están instaladas."""
    import shutil
    return {tool: shutil.which(tool) is not None for tool in tools}


def get_stealth_headers() -> Dict[str, str]:
    """Obtiene headers para OPSEC."""
    import random
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    return {
        "User-Agent": random.choice(uas),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
    }


def get_random_ua() -> str:
    """Obtiene un User-Agent aleatorio."""
    import random
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    ]
    return random.choice(uas)