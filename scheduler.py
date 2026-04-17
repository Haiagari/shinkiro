"""
BugBounty Framework — Scheduler 24/7
Modo continuo: watcher + diff + auto-scan de programas nuevos
Uso: 
  python scheduler.py --watch           # Modo watch (solo diff cuando cambia)
  python scheduler.py --daemon        # Modo daemon 24/7
  python scheduler.py --h1-new        # Buscar programas nuevos en H1
"""

import time
import argparse
import subprocess
import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime
from threading import Thread, Event

# Estado persistente
STATE_FILE = Path("output/.scheduler_state.json")

def load_state() -> dict:
    """Carga el estado del scheduler."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {
        "targets": {},
        "last_h1_check": None,
        "active": False,
    }

def save_state(state: dict):
    """Guarda el estado."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=4))

def log_sched(msg: str, level: str = "info"):
    """Log con colores."""
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"info": "\033[96m", "warn": "\033[93m", "error": "\033[91m", "success": "\033[92m"}
    color = colors.get(level, "\033[96m")
    print(f"{color}[SCHED] {ts} {msg}\033[0m")

def get_file_hash(filepath: Path) -> str:
    """Calcula hash de un archivo."""
    if not filepath.exists():
        return ""
    return hashlib.md5(filepath.read_bytes()).hexdigest()

def check_target_diff(target: str) -> dict:
    """
    Compara el estado actual vs anterior.
    Retorna qué cambió.
    """
    state = load_state()
    target_data = state.get("targets", {}).get(target, {})
    
    output_dir = Path("output") / target
    if not output_dir.exists():
        return {"is_first": True, "changes": []}
    
    changes = {
        "is_first": True if not target_data else False,
        "new_subdomains": [],
        "new_ports": [],
        "new_urls": [],
        "new_vulns": [],
        "changed_js": [],
    }
    
    # Comparar subdominios
    subs_file = output_dir / "recon" / "all_subdomains.txt"
    if subs_file.exists():
        old_hash = target_data.get("subdomains_hash", "")
        new_hash = get_file_hash(subs_file)
        if old_hash != new_hash and old_hash:
            old_subs = set(target_data.get("subdomains", []))
            new_subs = set([s.strip() for s in subs_file.read_text().splitlines()])
            changes["new_subdomains"] = list(new_subs - old_subs)
            changes["is_first"] = False
    
    # Comparar puertos
    ports_file = output_dir / "ports" / "naabu.txt"
    if ports_file.exists():
        old_ports = set(target_data.get("ports", []))
        new_ports = set([p.strip() for p in ports_file.read_text().splitlines() if p.strip()])
        changes["new_ports"] = list(new_ports - old_ports)
    
    # Comparar vulns
    vulns_file = output_dir / "vulns" / "nuclei.json"
    if vulns_file.exists():
        old_vulns = target_data.get("vulns_count", 0)
        new_vulns = len(vulns_file.read_text().splitlines())
        if new_vulns > old_vulns:
            changes["new_vulns"] = new_vulns - old_vulns
    
    return changes

def update_target_state(target: str, changes: dict):
    """Actualiza el estado después de un scan."""
    state = load_state()
    output_dir = Path("output") / target
    
    if not "targets" in state:
        state["targets"] = {}
    
    # Guardar hashes y datos actuales
    subs_file = output_dir / "recon" / "all_subdomains.txt"
    ports_file = output_dir / "ports" / "naabu.txt"
    vulns_file = output_dir / "vulns" / "nuclei.json"
    
    state["targets"][target] = {
        "last_scan": datetime.now().isoformat(),
        "subdomains_hash": get_file_hash(subs_file),
        "subdomains": list(set([s.strip() for s in subs_file.read_text().splitlines()])) if subs_file.exists() else [],
        "ports": list(set([p.strip() for p in ports_file.read_text().splitlines()])) if ports_file.exists() else [],
        "vulns_count": len(vulns_file.read_text().splitlines()) if vulns_file.exists() else 0,
    }
    
    save_state(state)

def run_scan(target: str, diff_only: bool = False):
    """
    Ejecuta un scan.
    Si diff_only=True, solo corre si hay cambios.
    """
    output_dir = Path("output") / target
    
    # Verificar si hay cambios
    if diff_only:
        changes = check_target_diff(target)
        has_changes = any([
            changes.get("new_subdomains"),
            changes.get("new_ports"),
            changes.get("new_vulns"),
            changes.get("changed_js"),
        ])
        
        if changes.get("is_first"):
            log_sched(f"Primera vez para {target} - ejecutando scan completo", "info")
        elif has_changes:
            log_sched(f"Cambios detectados en {target} - ejecutando scan", "warn")
            if changes.get("new_subdomains"):
                log_sched(f"  + {len(changes['new_subdomains'])} subdominios nuevos", "info")
            if changes.get("new_ports"):
                log_sched(f"  + {len(changes['new_ports'])} puertos nuevos", "info")
            if changes.get("new_vulns"):
                log_sched(f"  + {len(changes['new_vulns'])} vulns nuevas", "warn")
        else:
            log_sched(f"Sin cambios en {target} - saltando scan", "info")
            return {"skipped": True, "reason": "no_changes"}
    else:
        log_sched(f"Ejecutando scan para: {target}", "info")
    
    # Ejecutar main.py
    cmd = [sys.executable, "main.py", "-t", target, "--full"]
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1
        )
        
        # Mostrar output en tiempo real
        for line in process.stdout:
            if any(m in line for m in ["[+]", "[!]", "[-]", "[>]", "[*]", "[D]"]):
                print(f"  {line.strip()}")
        
        process.wait()
        
        if process.returncode == 0:
            log_sched(f"Scan completado: {target}", "success")
            update_target_state(target, {})
            return {"success": True}
        else:
            log_sched(f"Error en scan: {target} (code: {process.returncode})", "error")
            return {"success": False, "code": process.returncode}
            
    except Exception as e:
        log_sched(f"Error ejecutando: {e}", "error")
        return {"success": False, "error": str(e)}

def check_hackerone_new(hours: int = 2) -> list:
    """
    Busca programas nuevos en HackerOne.
    Retorna lista de programas publicados en las últimas N horas.
    """
    from modules.program_scraper import sync_program
    
    log_sched(f"Buscando programas nuevos en H1 (últimas {hours}h)...", "info")
    
    # Por ahora solo retornamos los programas populares
    # En una implementación completa, usarías la API de H1
    popular = [
        "google", "twitter", "shopify", "uber", "airbnb", 
        "gitlab", "wordpress", " Slack"
    ]
    
    # Simular check - en realidad revisarías la API
    new_programs = []
    state = load_state()
    last_check = state.get("last_h1_check")
    
    if last_check:
        last_dt = datetime.fromisoformat(last_check)
        # Solo retornar algo si es reciente
        new_programs = []  # Placeholder
    
    state["last_h1_check"] = datetime.now().isoformat()
    save_state(state)
    
    log_sched(f"Programas nuevos: {len(new_programs)}", "info")
    return new_programs

def run_scheduler_daemon(interval_hours: int = 6, diff_only: bool = True):
    """
    Modo daemon: corre continuamente.
    """
    state = load_state()
    state["active"] = True
    save_state(state)
    
    log_sched("=" * 50, "info")
    log_sched("INICIANDO SCHEDULER 24/7", "success")
    log_sched(f"Intervalo: {interval_hours}h | Modo: {'DIFF' if diff_only else 'FULL'}", "info")
    log_sched("=" * 50, "info")
    
    targets_file = Path("targets.txt")
    if not targets_file.exists():
        targets_file.write_text("")
    
    cycle = 0
    while state["active"]:
        cycle += 1
        log_sched(f"\n--- CICLO {cycle} ---", "info")
        
        # Cargar targets
        targets = [t.strip() for t in targets_file.read_text().splitlines() if t.strip()]
        
        if not targets:
            log_sched("Sin targets. Esperando...", "warn")
            time.sleep(300)
            continue
        
        log_sched(f"{len(targets)} targets activa(s)", "info")
        
        for target in targets:
            result = run_scan(target, diff_only=diff_only)
            
            if result.get("skipped"):
                log_sched(f"  └ {target}: omitido (sin cambios)", "info")
            elif result.get("success"):
                log_sched(f"  └ {target}: completado", "success")
            else:
                log_sched(f"  └ {target}: error", "error")
            
            # Delay entre targets
            time.sleep(10)
        
        log_sched(f"Ciclo {cycle} completado. Durmiendo {interval_hours}h...", "info")
        time.sleep(interval_hours * 3600)

def run_watch_mode(target: str):
    """
    Modo watch: observa un target específico.
    """
    log_sched(f"MODO WATCH: {target}", "warn")
    log_sched("Esperando cambios... (Ctrl+C para salir)", "info")
    
    while True:
        changes = check_target_diff(target)
        
        has_changes = any([
            changes.get("new_subdomains"),
            changes.get("new_ports"), 
            changes.get("new_vulns"),
            changes.get("changed_js"),
        ])
        
        if has_changes:
            log_sched("¡CAMBIO DETECTADO!", "warn")
            
            if changes.get("new_subdomains"):
                log_sched(f"  🌐 {len(changes['new_subdomains'])} subdominios nuevos", "warn")
                for s in changes["new_subdomains"][:3]:
                    log_sched(f"     - {s}", "info")
            
            if changes.get("new_vulns"):
                log_sched(f"  🔥 {changes['new_vulns']} vulns nuevas", "error")
            
            # Auto-scan?
            log_sched("Ejecutando scan de seguimiento...", "info")
            run_scan(target, diff_only=False)
        else:
            log_sched(f"  {datetime.now().strftime('%H:%M:%S')} - Sin cambios", "info")
        
        time.sleep(300)  # Check cada 5 min

def main():
    p = argparse.ArgumentParser(description="BugBounty Scheduler 24/7")
    p.add_argument("-t", "--target", help="Target específico")
    p.add_argument("-l", "--list", default="targets.txt", help="Archivo de targets")
    p.add_argument("-i", "--interval", type=int, default=6, help="Intervalo en horas (default: 6)")
    p.add_argument("--watch", action="store_true", help="Modo watch (observar un target)")
    p.add_argument("--daemon", action="store_true", help="Modo daemon 24/7")
    p.add_argument("--diff", action="store_true", default=True, help="Solo escanear si hay cambios")
    p.add_argument("--full", action="store_true", help="Scan completo siempre")
    p.add_argument("--h1-new", action="store_true", help="Buscar programas nuevos en H1")
    args = p.parse_args()
    
    if args.watch and args.target:
        run_watch_mode(args.target)
    elif args.daemon:
        run_scheduler_daemon(args.interval, diff_only=not args.full)
    elif args.h1_new:
        check_hackerone_new()
    elif args.target:
        run_scan(args.target, diff_only=not args.full)
    else:
        # Default: daemon
        run_scheduler_daemon(args.interval, diff_only=not args.full)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_sched("Scheduler detenido.", "warn")
        
        # Desactivar
        state = load_state()
        state["active"] = False
        save_state(state)
        
        sys.exit(0)