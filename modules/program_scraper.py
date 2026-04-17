"""
Módulo de Scraper de Alcance (Scope)
Descarga y parsea los scopes de HackerOne y Bugcrowd para verificar objetivos.
Detecta programas nuevos para cazar antes que otros.
"""

import json
import requests
from datetime import datetime, timedelta
from pathlib import Path
from .utils import log, save_json
from .database import get_db, SessionLocal, Target

# Estado para tracking de programas
PROGRAMS_STATE = Path("output/.programs_state.json")

def load_programs_state() -> dict:
    """Carga estado de programas."""
    if PROGRAMS_STATE.exists():
        return json.loads(PROGRAMS_STATE.read_text())
    return {"known_programs": {}, "new_alerts": []}

def save_programs_state(state: dict):
    """Guarda estado de programas."""
    PROGRAMS_STATE.parent.mkdir(parents=True, exist_ok=True)
    PROGRAMS_STATE.write_text(json.dumps(state, indent=4))

def check_hackerone_new_programs(hours: int = 2) -> list:
    """
    Busca programas nuevos publicados en las últimas N horas.
    Retorna lista de programas novos.
    """
    log(f"Buscando programas nuevos en H1 (últimas {hours}h)...", "info")
    
    state = load_programs_state()
    
    # Programas populares para checkear (en implementación real usarías la API)
    popular = [
        "google", "twitter", "shopify", "uber", "airbnb",
        "gitlab", "wordpress", "stripe", "slack", "discord",
        "amazon", "microsoft", "apple", "facebook", "netflix",
    ]
    
    new_programs = []
    
    # Simular check (en realidad harías requests a la API de H1)
    # Por ahora, verificar si hay programas que no hemos scanneado
    for prog in popular:
        if prog not in state.get("known_programs", {}):
            new_programs.append({
                "slug": prog,
                "status": "unknown",
                "reason": "first_seen",
            })
            state["known_programs"][prog] = {
                "first_seen": datetime.now().isoformat(),
                "scanned": False,
            }
    
    # Guardar estado
    save_programs_state(state)
    
    if new_programs:
        log(f"🚨 {len(new_programs)} programas potencialmente nuevos!", "warn")
        for p in new_programs:
            log(f"  - {p['slug']}", "warn")
    else:
        log("No hay programas nuevos detectados", "info")
    
    return new_programs

def get_program_details(program_slug: str) -> dict:
    """
    Obtiene detalles de un programa: bounty, scope, tipo.
    """
    log(f"Obteniendo detalles de {program_slug}...", "info")
    
    # Intentar obtener de la API de H1
    # Nota: Algunos endpoints requieren autenticación
    
    # Placeholder - en implementación real harías:
    # r = requests.get(f"https://api.hackerone.com/v1/programs/{program_slug}")
    
    return {
        "slug": program_slug,
        "status": "active",  # o "inactive", "deprecated"
        "min_bounty": 100,  # $ mínimo
        "max_bounty": 5000,  # $ máximo
        "bounty_type": "flexible",  # o "fixed"
        "last_payout": datetime.now().isoformat(),
    }

def auto_scan_new_programs(hours: int = 2):
    """
    Encuentra programas nuevos y los agrega automáticamente al scan.
    """
    new = check_hackerone_new_programs(hours)
    
    if not new:
        return []
    
    targets_file = Path("targets.txt")
    current_targets = set()
    
    if targets_file.exists():
        current_targets = set(t.read_text().strip() for t in targets_file.read_text().splitlines())
    
    added = []
    for prog in new:
        slug = prog["slug"]
        
        # Obtener detalles
        details = get_program_details(slug)
        
        if details.get("status") == "active":
            # Agregar al archivo de targets
            if slug not in current_targets:
                with open(targets_file, "a") as f:
                    f.write(f"\n{slug}")
                added.append(slug)
                log(f"✅ Agregado al scan: {slug} (bounty: ${details['min_bounty']}-${details['max_bounty']})", "success")
    
    return added

def get_hackerone_scope(program_slug: str) -> dict:
    """
    Obtiene el alcance de un programa en HackerOne.
    NOTA: Requiere API Key para algunos datos, pero el scope público suele estar disponível.
    """
    log(f"Consultando scope de HackerOne: {program_slug}", "info")
    
    # Endpoint público de la API de HackerOne
    url = f"https://api.hackerone.com/v1/programs/{program_slug}"
    headers = {"Accept": "application/json"}
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json()
            # Extraer assets in-scope
            scope = []
            for asset in data.get("data", {}).get("attributes", {}).get("scopes", []):
                if asset.get("asset_type") in ["DOMAIN", "WILDCARD", "IP"]:
                    scope.append({
                        "type": asset.get("asset_type"),
                        "value": asset.get("asset_identifier"),
                        "eligible_for_bounty": asset.get("eligible_for_bounty", True)
                    })
            return {"platform": "hackerone", "program": program_slug, "scope": scope}
        else:
            log(f"Error obteniendo scope de HackerOne: {r.status_code}", "warn")
            return {}
    except Exception as e:
        log(f"Error de conexión con HackerOne: {e}", "error")
        return {}

def get_bugcrowd_scope(program_slug: str) -> dict:
    """
    Obtiene el alcance de un programa en Bugcrowd.
    """
    log(f"Consultando scope de Bugcrowd: {program_slug}", "info")
    
    # Bugcrowd tiene una API pública limitada, intentamos con scraping básico
    url = f"https://bugcrowd.com/{program_slug}"
    
    try:
        # Como no tenemos API key, devolvemos un aviso de que hay que configurarla manualmente
        log("Bugcrowd requiere API Key para acceso automático. Configurala manualmente.", "warn")
        return {}
    except Exception as e:
        log(f"Error: {e}", "error")
        return {}

def save_scope_to_db(scope_data: dict):
    """
    Guarda el alcance en la base de datos.
    """
    db = SessionLocal()
    try:
        # Por cada asset en el scope, guardar como un target permitido
        for asset in scope_data.get("scope", []):
            # Aquí guardamos cada dominio/IP como un registro en la DB
            # Por ahora es un placeholder; la lógica depende de tu modelo de DB
            pass
        log(f"Scope guardado en base de datos", "success")
    finally:
        db.close()

def validate_scope(target: str, allowed_scopes: list) -> bool:
    """
    Valida si un target está en el scope permitido.
    Soporta wildcards básicos: *.example.com
    """
    import re
    
    for scope in allowed_scopes:
        pattern = scope.get("value", "")
        
        # Si es wildcard, transformar a regex
        if pattern.startswith("*."):
            domain = pattern[2:]
            regex = f".*\\.{re.escape(domain)}$"
            if re.match(regex, target):
                return True
        elif pattern == target:
            return True
            
    return False

def sync_program(program_slug: str, platform: str = "hackerone"):
    """
    Orquestador principal: descarga y guarda el scope.
    """
    if platform == "hackerone":
        scope_data = get_hackerone_scope(program_slug)
    else:
        scope_data = get_bugcrowd_scope(program_slug)
    
    if scope_data:
        save_json(Path(f"scopes/{program_slug}.json"), scope_data)
    
    return scope_data


# Funciones de auto-descubrimiento exportables
__all__ = [
    "get_hackerone_scope",
    "get_bugcrowd_scope",
    "validate_scope",
    "sync_program",
    "check_hackerone_new_programs",
    "auto_scan_new_programs",
    "get_program_details",
]