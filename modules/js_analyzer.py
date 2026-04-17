"""
Módulo de Análisis de JavaScript
Busca secretos, API Keys y endpoints ocultos en archivos JS.
"""

import re
import requests
import hashlib
from pathlib import Path
from .utils import log, save_json, dedupe

# Patrones de búsqueda de secretos (Simplificado pero efectivo)
SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
    "Generic Token/Key": r"(?i)(key|token|secret|auth|password|creds)[-|_| ]*[:|=][-|_| ]*['|\"]([0-9a-zA-Z]{10,60})['|\"]",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
}

ENDPOINT_PATTERN = r"['|\"](/[a-zA-Z0-9._\-/]+)['|\"]"

def run_js_analyzer(target: str, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Analiza archivos JS en busca de secretos y endpoints.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log("Iniciando análisis de archivos JavaScript...", "info")

    js_files = context.get("phases", {}).get("urls", {}).get("js_files", [])
    if not js_files:
        log("No se encontraron archivos JS para analizar.", "warn")
        return {"secrets": [], "endpoints": [], "hashes": {}}

    log(f"Analizando {len(js_files[:30])} archivos JS (muestra)...", "info")
    
    all_secrets = []
    all_endpoints = []
    js_hashes = {}

    # Limitamos para no tardar una eternidad en el primer prototipo
    for js_url in js_files[:30]:
        try:
            # En una versión madura, esto sería async con httpx
            r = requests.get(js_url, timeout=args.timeout, verify=False)
            if r.status_code == 200:
                content = r.text
                
                # Calcular Hash del contenido (Sprint 5)
                js_hash = hashlib.sha256(content.encode()).hexdigest()
                js_hashes[js_url] = js_hash
                
                # Buscar Secretos
                for name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    for m in matches:
                        # Si es el pattern genérico, viene como tupla
                        val = m[1] if isinstance(m, tuple) else m
                        all_secrets.append({
                            "type": name,
                            "value": val,
                            "source": js_url
                        })
                
                # Buscar Endpoints
                endpoints = re.findall(ENDPOINT_PATTERN, content)
                for ep in endpoints:
                    if len(ep) > 3 and "/" in ep: # Filtrar basura
                        all_endpoints.append({
                            "endpoint": ep,
                            "source": js_url
                        })
                        
        except Exception as e:
            continue

    all_secrets = dedupe([f"{s['type']}:{s['value']}" for s in all_secrets])
    all_endpoints = dedupe([e["endpoint"] for e in all_endpoints])

    results = {
        "secrets": all_secrets,
        "endpoints": all_endpoints,
        "hashes": js_hashes,
        "files_analyzed": len(js_files[:30])
    }

    save_json(out_dir / "results.json", results)
    log(f"Análisis JS completado: {len(all_secrets)} secretos encontrados.", "success")
    
    return results
