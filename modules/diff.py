"""
Módulo de Diferencias (Diff Engine)
Compara los resultados actuales con la ejecución anterior para detectar cambios.
"""

import json
from pathlib import Path
from .utils import log, save_json, load_json

def run_diff(target: str, out_dir: Path, context: dict = {}) -> dict:
    """
    Compara la sesión actual con la anterior más reciente.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log("Iniciando motor de diferencias (Diff Engine)...", "info")

    # 1. Buscar la última sesión exitosa
    # Estructura: output/target/timestamp/recon/results.json
    base_dir = Path(context.get("out_dir", ".")).parent.parent # output/target/
    sessions = sorted([d for d in base_dir.iterdir() if d.is_dir()], reverse=True)
    
    # La sesión actual es sessions[0], buscamos sessions[1]
    if len(sessions) < 2:
        log("No hay sesiones anteriores para comparar (Primera ejecución).", "info")
        return {"new_subdomains": [], "new_ports": [], "new_vulns": [], "is_first_run": True}

    last_session = sessions[1]
    log(f"Comparando con la última sesión: {last_session.name}", "info")

    # 2. Cargar datos actuales
    current = context.get("phases", {})
    
    # 3. Cargar datos anteriores (de los results.json de cada fase)
    prev_recon = load_json(last_session / "recon" / "results.json")
    prev_ports = load_json(last_session / "ports" / "results.json")
    prev_vulns = load_json(last_session / "vulns" / "results.json")

    # 4. Comparar Subdominios
    curr_subs = set(current.get("recon", {}).get("all_subdomains", []))
    old_subs  = set(prev_recon.get("all_subdomains", []))
    new_subs  = list(curr_subs - old_subs)

    # 5. Comparar Puertos
    curr_ports = set(current.get("ports", {}).get("open_ports", []))
    old_ports  = set(prev_ports.get("open_ports", []))
    new_ports  = list(curr_ports - old_ports)

    # 6. Comparar Vulnerabilidades
    curr_findings = current.get("vulns", {}).get("findings", [])
    old_findings = prev_vulns.get("findings", [])
    new_vulns = len(curr_findings) - len(old_findings)

    # 7. Comparar Cambios en JS (Sprint 5)
    curr_js = current.get("js_analysis", {}).get("hashes", {})
    prev_js = load_json(last_session / "js_analysis" / "results.json").get("hashes", {})
    changed_js = []
    for url, js_hash in curr_js.items():
        if url in prev_js and prev_js[url] != js_hash:
            changed_js.append(url)

    results = {
        "new_subdomains": new_subs,
        "new_ports": new_ports,
        "new_vulns": new_vulns,
        "changed_js": changed_js,
        "is_first_run": False
    }

    save_json(out_dir / "results.json", results)

    if new_subs: log(f"NUEVOS SUBDOMINIOS: {len(new_subs)}", "warn")
    if new_ports: log(f"NUEVOS PUERTOS: {len(new_ports)}", "warn")
    if new_vulns: log(f"NUEVAS VULNERABILIDADES: {len(new_vulns)}", "error")
    if changed_js: log(f"ARCHIVOS JS CAMBIADOS: {len(changed_js)}", "warn")

    return results
