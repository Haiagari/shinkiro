"""Utilidades compartidas de OzyRecon"""

import sys
import subprocess
import shutil
import yaml
import json
import logging
from pathlib import Path
from datetime import datetime

# Configuración de logging profesional
logger = logging.getLogger("ozyrecon")
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


def load_config(path: str = "config/config.yaml") -> dict:
    root_dir = Path(__file__).resolve().parents[2]
    cfg_path = Path(path)

    candidates = [cfg_path]
    if not cfg_path.is_absolute():
        candidates = [root_dir / cfg_path, root_dir / "config" / cfg_path.name]

    for candidate in candidates:
        if candidate.exists():
            with open(candidate) as f:
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


import random

# ══════════════════════════════════════════════════════════════════════════════
# OPSEC - SIGILO Y EVASIÓN
# ══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
]

def get_random_ua() -> str:
    """Devuelve un User-Agent aleatorio de la lista."""
    return random.choice(USER_AGENTS)

def get_stealth_headers(include_bugbounty_header: bool = True) -> dict:
    """Retorna headers de alta reputación para evadir WAFs (Cloudflare/Akamai).
    
    Args:
        include_bugbounty_header: Si True, agrega el header X-Bug-Bounty si está configurado.
    """
    import random
    
    browsers = [
        ("Chrome", "120.0.0.0", "AppleWebKit/537.36"),
        ("Firefox", "121.0", "Gecko/20100101"),
        ("Safari", "17.2", "AppleWebKit/605.1.15")
    ]
    os_list = [
        "Windows NT 10.0; Win64; x64", 
        "Macintosh; Intel Mac OS X 10_15_7", 
        "X11; Linux x86_64"
    ]
    
    browser_name, version, engine = random.choice(browsers)
    opsys = random.choice(os_list)
    
    ua = f"Mozilla/5.0 ({opsys}) {engine} (KHTML, like Gecko) {browser_name}/{version}"
    
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    
    # Agregar header de Bug Bounty si está configurado
    if include_bugbounty_header:
        bb_config = load_config().get("bugbounty_header", {})
        if bb_config.get("enabled") and bb_config.get("header_name") and bb_config.get("header_value"):
            headers[bb_config["header_name"]] = bb_config["header_value"]
    
    return headers


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
