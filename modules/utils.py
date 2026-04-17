"""Utilidades compartidas del framework"""

import sys
import subprocess
import shutil
import yaml
import json
import logging
from pathlib import Path
from datetime import datetime

# Configuración de logging profesional
logger = logging.getLogger("bugbounty")
logger.setLevel(logging.DEBUG)

# Handler para consola
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)

# Formateador con colores para consola
class CustomFormatter(logging.Formatter):
    grey = "\033[90m"
    blue = "\033[94m"
    yellow = "\033[93m"
    red = "\033[91m"
    bold_red = "\033[1;91m"
    reset = "\033[0m"
    
    FORMATS = {
        logging.DEBUG: f"{grey}[D] %(message)s{reset}",
        logging.INFO: f"{blue}[*] %(message)s{reset}",
        logging.WARNING: f"{yellow}[!] %(message)s{reset}",
        logging.ERROR: f"{red}[-] %(message)s{reset}",
        logging.CRITICAL: f"{bold_red}[CRITICAL] %(message)s{reset}"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

console_handler.setFormatter(CustomFormatter())
if not logger.handlers:
    logger.addHandler(console_handler)

def log(msg: str, level: str = "info"):
    """
    Wrapper para mantener compatibilidad y añadir estilos especiales.
    """
    if level == "phase":
        logger.info(f"\033[96m[>] {msg.upper()}\033[0m")
    elif level == "success":
        logger.info(f"\033[92m[+] {msg}\033[0m")
    elif level == "sep":
        logger.info(f"\033[90m{'═' * 55}\033[0m")
    elif level == "warn":
        logger.warning(msg)
    elif level == "error":
        logger.error(msg)
    else:
        logger.info(msg)


def banner():
    b = f"""\033[1m\033[96m
  ██████╗ ██╗   ██╗ ██████╗     ██████╗ ██████╗ 
  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔══██╗
  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██████╔╝
  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██╔══██╗
  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝██████╔╝
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝ ╚═════╝ 
  Bug Bounty Automation Framework v1.0
\033[0m"""
    print(b)


def load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(path)
    if cfg_path.exists():
        with open(cfg_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def tool_exists(tool: str) -> bool:
    """Verifica si una herramienta está instalada en PATH."""
    return shutil.which(tool) is not None


def check_tools(tools: list) -> dict:
    """Devuelve dict {tool: bool} con disponibilidad."""
    return {t: tool_exists(t) for t in tools}


def run_cmd(cmd: str, out_file: Path = None, timeout: int = 300) -> tuple[int, str]:
    """
    Ejecuta un comando de shell.
    Si out_file se proporciona, guarda stdout ahí.
    Retorna (returncode, stdout_str).
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if out_file and output:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(output)
        return result.returncode, output
    except subprocess.TimeoutExpired:
        log(f"Timeout ejecutando: {cmd}", "warn")
        return 1, ""
    except Exception as e:
        log(f"Error ejecutando '{cmd}': {e}", "error")
        return 1, ""


def read_lines(path: Path) -> list:
    """Lee un archivo línea por línea, ignora vacíos."""
    if not path or not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]


def write_lines(path: Path, lines: list):
    """Escribe lista de strings a archivo, uno por línea."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def dedupe(lst: list) -> list:
    """Elimina duplicados manteniendo orden."""
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))]


def save_json(path: Path, data: dict):
    """Guarda resultados en JSON estructurado."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)
    logger.debug(f"JSON guardado en: {path}")


def load_json(path: Path) -> dict:
    """Carga un JSON si existe."""
    if not path.exists(): return {}
    with open(path) as f:
        return json.load(f)


def send_telegram(message: str, config: dict):
    """Envía una alerta a Telegram."""
    token = config.get("notifications", {}).get("telegram_token")
    chat_id = config.get("notifications", {}).get("telegram_chat_id")
    if not token or not chat_id:
        return
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        import requests
        requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        logger.error(f"Error enviando Telegram: {e}")

