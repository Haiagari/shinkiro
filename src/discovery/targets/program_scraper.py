"""
Módulo de Scraper de Alcance (Scope)
Descarga y parsea los scopes de HackerOne y Bugcrowd para verificar objetivos.
Detecta programas nuevos para cazar antes que otros.
"""

import requests
from pathlib import Path
from src.utils import log, save_json, load_config
from src.storage.database import SessionLocal
from src.storage.queries import DBQueries
from src.storage.models import Target

def get_hackerone_scope(program_slug: str) -> dict:
    """
    Obtiene el alcance de un programa en HackerOne.
    Enhanced: Usa API Key y Username para autenticación.
    """
    log(f"Consultando scope de HackerOne: {program_slug}", "info")
    
    config = load_config()
    api_key = config.get("bugbounty", {}).get("hackerone_api_key")
    username = config.get("bugbounty", {}).get("hackerone_username")

    # Endpoint de la API de HackerOne
    url = f"https://api.hackerone.com/v1/programs/{program_slug}"
    headers = {"Accept": "application/json"}
    
    auth = None
    if api_key and username:
        from requests.auth import HTTPBasicAuth
        auth = HTTPBasicAuth(username, api_key)
    else:
        log("No se encontraron credenciales de H1. Intentando acceso público...", "warn")
    
    try:
        r = requests.get(url, headers=headers, auth=auth, timeout=30)
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

def _scope_entry_to_target_fields(asset: dict, platform: str, program_slug: str) -> dict:
    raw_value = (asset.get("value") or "").strip()
    normalized_value = raw_value.lower()
    eligible = bool(asset.get("eligible_for_bounty", True))

    notes = (
        f"Imported from {platform}:{program_slug}. "
        f"Asset type={asset.get('type', 'unknown')}. "
        f"Eligible for bounty={eligible}."
    )

    tags = [platform, "bugbounty", "scope"]
    if eligible:
        tags.append("bounty")

    return {
        "domain": normalized_value,
        "in_scope": 1,
        "notes": notes,
        "tags": tags,
    }


def save_scope_to_db(scope_data: dict):
    """
    Guarda el alcance en la base de datos.
    """
    db = SessionLocal()
    try:
        platform = scope_data.get("platform", "unknown")
        program_slug = scope_data.get("program", "unknown")
        dbq = DBQueries(db)

        saved = 0
        for asset in scope_data.get("scope", []):
            fields = _scope_entry_to_target_fields(asset, platform, program_slug)
            domain = fields["domain"]
            if not domain:
                continue

            existing = dbq.get_target(domain)
            if existing:
                existing.in_scope = fields["in_scope"]
                existing.notes = fields["notes"]
                existing.tags = fields["tags"]
            else:
                db.add(Target(**fields))
            saved += 1

        db.commit()
        log(f"Scope guardado en base de datos ({saved} assets)", "success")
        return saved
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
