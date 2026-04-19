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

from .js_linkfinder import run_js_discovery

def run_js_analyzer(target: str, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Analiza archivos JS en busca de secretos y endpoints (Enhanced with LinkFinder).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log("Iniciando análisis profundo de archivos JavaScript...", "info")

    js_files = context.get("phases", {}).get("urls", {}).get("js_files", [])
    if not js_files:
        log("No se encontraron archivos JS para analizar.", "warn")
        return {"secrets": [], "endpoints": [], "hashes": {}}

    log(f"Analizando {len(js_files[:50])} archivos JS con LinkFinder...", "info")
    
    # 1. Ejecutar LinkFinder Nativo
    linkfinder_results = run_js_discovery(js_files[:50], out_dir / "linkfinder")
    all_endpoints = linkfinder_results.get("endpoints", [])
    
    all_secrets = []
    js_hashes = {}

    # 2. Análisis de Secretos y Hashes
    for js_url in js_files[:30]:
        try:
            r = requests.get(js_url, timeout=args.timeout, verify=False)
            if r.status_code == 200:
                content = r.text
                js_hashes[js_url] = hashlib.sha256(content.encode()).hexdigest()
                
                for name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content)
                    for m in matches:
                        val = m[1] if isinstance(m, tuple) else m
                        all_secrets.append({"type": name, "value": val, "source": js_url})
        except: continue

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
