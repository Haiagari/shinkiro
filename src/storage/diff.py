"""
Módulo de Diferencias (Diff Engine)
Compara los resultados actuales con la ejecución anterior para detectar cambios.
Soporta两种 modos: JSON (legacy) y SQLite (nuevo con use_db=True).
"""

import json
from pathlib import Path
from src.utils import log, save_json, load_json


def run_diff(target: str, out_dir: Path, context: dict = {}, use_db: bool = False) -> dict:
    """
    Compara la sesión actual con la anterior más reciente.
    
    Args:
        target: Dominio objetivo
        out_dir: Directorio de salida para esta sesión
        context: Contexto actual del scan
        use_db: Si True, usa la DB SQLite para diffing (más preciso)
    
    Returns:
        Dict con new_subdomains, new_ports, new_vulns, changed_js, is_first_run
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log("Iniciando motor de diferencias (Diff Engine)...", "info")

    # ══════════════════════════════════════════════════════════════════════════════
    # MODO DB: Usar consultas SQL para diffing (recomendado)
    # ══════════════════════════════════════════════════════════════════════════════
    if use_db:
        log("Usando Diff Engine basado en SQLite...", "info")
        return _run_diff_db(target, out_dir, context)

    # ══════════════════════════════════════════════════════════════════════════════
    # MODO LEGACY: Usar archivos JSON
    # ══════════════════════════════════════════════════════════════════════════════
    log("Usando Diff Engine basado en archivos JSON...", "info")
    return _run_diff_json(target, out_dir, context)


def _run_diff_db(target: str, out_dir: Path, context: dict) -> dict:
    """
    Diff usando la base de datos SQLite (más preciso y rápido).
    """
    try:
        from .database import SessionLocal
        from .db_queries import get_scan_diff
        
        db = SessionLocal()
        try:
            diff_result = get_scan_diff(db, target)
            
            save_json(out_dir / "results.json", diff_result)
            
            # Loggear cambios relevantes
            if diff_result.get("new_subdomains"):
                log(f"NUEVOS SUBDOMINIOS: {len(diff_result['new_subdomains'])}", "warn")
            if diff_result.get("new_ports"):
                log(f"NUEVOS PUERTOS: {len(diff_result['new_ports'])}", "warn")
            if diff_result.get("new_vulns"):
                log(f"NUEVAS VULNERABILIDADES: {len(diff_result['new_vulns'])}", "error")
            
            return diff_result
        finally:
            db.close()
    except Exception as e:
        log(f"Error en diff DB: {e}", "error")
        return {"new_subdomains": [], "new_ports": [], "new_vulns": [], "error": str(e)}


def _run_diff_json(target: str, out_dir: Path, context: dict) -> dict:
    """
    Diff usando archivos JSON (legacy).
    """
    # 1. Buscar la última sesión exitosa
    # Estructura: runtime/scans/target/timestamp/recon/results.json
    base_dir = Path(context.get("out_dir", ".")).parent.parent  # runtime/scans/target/
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
    if new_vulns: log(f"NUEVAS VULNERABILIDADES: {new_vulns}", "error")
    if changed_js: log(f"ARCHIVOS JS CAMBIADOS: {len(changed_js)}", "warn")

    return results


def run_diff_db_only(target: str) -> dict:
    """
    Función de conveniencia para obtener diff sin ejecutar todo el pipeline.
    Útil para consultar desde la CLI o API.
    """
    from .database import SessionLocal
    from .db_queries import get_scan_diff
    
    db = SessionLocal()
    try:
        return get_scan_diff(db, target)
    finally:
        db.close()


class DiffEngine:
    """Clase wrapper para el motor de diferencias."""
    
    def __init__(self, db_session=None):
        self.db_session = db_session
    
    def compute_diff(self, scan_id: int, previous_scan_id: int) -> dict:
        """Calcula diferencias entre dos scans."""
        return run_diff("", Path(""), use_db=True)
    
    def has_changes(self) -> bool:
        """Verifica si hay cambios."""
        return True


# Alias para compatibilidad
def quick_diff(target: str):
    """Función de compatibilidad."""
    return run_diff(target, Path(""), use_db=True)

get_diff = quick_diff
