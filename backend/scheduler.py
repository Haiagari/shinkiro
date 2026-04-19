"""
BugBounty Framework — Scheduler 24/7 (v2.0)
Modo continuo 2.0: daemon + diff + micro-scans focalizados
Soporta estado en SQLite o JSON legacy.

Uso: 
  python3 backend/scheduler.py --watch        # Modo watch (solo diff cuando cambia)
  python3 backend/scheduler.py --daemon       # Modo daemon 24/7
  python3 backend/scheduler.py --h1-new       # Buscar programas nuevos en H1
  python3 backend/scheduler.py --micro-scan   # Micro-scan focalizado (solo fases que cambiaron)
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
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
RUNTIME_DIR = ROOT_DIR / "runtime"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Intentar importar módulos del framework
try:
    from modules.database import SessionLocal, init_db
    from modules.models import Target, Scan
    from modules.db_queries import get_scan_diff
    HAS_DB = True
except ImportError:
    HAS_DB = False
    print("[WARN] DB no disponible - usando modo legacy JSON")

# Estado persistente legacy (si no hay DB)
STATE_FILE = RUNTIME_DIR / "state" / ".scheduler_state.json"

def load_state() -> dict:
    """Carga el estado del scheduler (legacy JSON)."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {
        "targets": {},
        "last_h1_check": None,
        "active": False,
    }

def save_state(state: dict):
    """Guarda el estado (legacy JSON)."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=4))

# ══════════════════════════════════════════════════════════════════════════════
# NUEVO: Funciones de estado basadas en SQLite
# ══════════════════════════════════════════════════════════════════════════════

def get_last_scan_from_db(target: str) -> Optional[Scan]:
    """Obtiene el último scan completado de un target desde la DB."""
    if not HAS_DB:
        return None
    
    db = SessionLocal()
    try:
        target_obj = db.query(Target).filter(Target.domain == target).first()
        if not target_obj:
            return None
        
        # Obtener el último scan ordenado por timestamp
        last_scan = db.query(Scan).filter(
            Scan.target_id == target_obj.id,
            Scan.status == "completed"
        ).order_by(Scan.timestamp.desc()).first()
        
        return last_scan
    finally:
        db.close()

def get_target_subs_from_db(target: str) -> set:
    """Obtiene todos los subdominios conocidos de un target desde la DB."""
    if not HAS_DB:
        return set()
    
    db = SessionLocal()
    try:
        target_obj = db.query(Target).filter(Target.domain == target).first()
        if not target_obj:
            return set()
        
        from modules.models import Subdomain
        subs = db.query(Subdomain).join(Scan).filter(
            Scan.target_id == target_obj.id,
            Subdomain.is_live == 1
        ).all()
        
        return {s.domain for s in subs}
    finally:
        db.close()

def get_target_ports_from_db(target: str) -> set:
    """Obtiene todos los puertos conocidos de un target desde la DB."""
    if not HAS_DB:
        return set()
    
    db = SessionLocal()
    try:
        target_obj = db.query(Target).filter(Target.domain == target).first()
        if not target_obj:
            return set()
        
        from modules.models import Port
        ports = db.query(Port).join(Scan).filter(
            Scan.target_id == target_obj.id
        ).all()
        
        return {f"{p.host}:{p.port}" for p in ports}
    finally:
        db.close()

def check_target_diff_v2(target: str) -> dict:
    """
    Compara el estado actual vs anterior (v2 - usa DB cuando available).
    Retorna qué cambió y qué fases deben ejecutarse.
    """
    # Cargar estado legacy si no hay DB
    if not HAS_DB:
        return _check_target_diff_legacy(target)
    
    # Usar DB para diff
    db = SessionLocal()
    try:
        diff_result = get_scan_diff(db, target)
        
        if not diff_result or diff_result.get("is_first_run"):
            return {
                "is_first": True,
                "changes": [],
                "phases_to_run": ["full"],  # Todo
            }
        
        phases_to_run = []
        
        if diff_result.get("new_subdomains"):
            phases_to_run.append("recon")
        if diff_result.get("new_ports"):
            phases_to_run.append("ports")
        if diff_result.get("new_vulns"):
            phases_to_run.append("vulns")
        
        return {
            "is_first": False,
            "new_subdomains": diff_result.get("new_subdomains", []),
            "new_ports": diff_result.get("new_ports", []),
            "new_vulns": diff_result.get("new_vulns", 0),
            "changes": diff_result,
            "phases_to_run": phases_to_run if phases_to_run else ["diff"],  # Mínimo diff
        }
        
    except Exception as e:
        print(f"[ERROR] Diff v2 failed: {e}")
        return _check_target_diff_legacy(target)
    finally:
        db.close()

def _check_target_diff_legacy(target: str) -> dict:
    """Diff legacy usando archivos (fallback)."""

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
    
    output_dir = RUNTIME_DIR / "scans" / target
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
    output_dir = RUNTIME_DIR / "scans" / target
    
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

def run_scan(target: str, diff_only: bool = False, micro_scan: bool = True, use_agent: bool = True):
    """
    Ejecuta un scan. 
    Si use_agent=True, delega el criterio al Agente IA (Modo Continuo).
    """
    output_dir = RUNTIME_DIR / "scans" / target
    
    # 1. Si el usuario quiere inteligencia, delegamos al Agente
    if use_agent and HAS_DB:
        log_sched(f"Delegando monitoreo de {target} al Agente IA...", "info")
        try:
            from modules.agent import BugBountyAgent
            agent = BugBountyAgent()
            # El agente maneja su propio loop de razonamiento y ejecución
            result = agent.run("continuo", target)
            log_sched(f"Agente finalizó monitoreo de {target} ({result['steps']} pasos)", "success")
            return {"success": True}
        except Exception as e:
            log_sched(f"Falla en Agente, cayendo a modo tradicional: {e}", "warn")

    # 2. Modo tradicional (Legacy/Fallback)
    if diff_only:
        if HAS_DB:
            changes = check_target_diff_v2(target)
        else:
            changes = check_target_diff(target)
        
        has_changes = any([changes.get("new_subdomains"), changes.get("new_ports"), changes.get("new_vulns")])
        
        if changes.get("is_first"):
            log_sched(f"Primera vez para {target} - ejecutando scan completo", "info")
        elif micro_scan and HAS_DB and changes.get("phases_to_run"):
            phases = changes.get("phases_to_run", [])
            log_sched(f"Cambios detectados - ejecutando micro-scan tradicional: {phases}", "warn")
            return run_micro_scan(target, phases)
        elif not has_changes:
            log_sched(f"Sin cambios en {target} - saltando", "info")
            return {"skipped": True}

    # Scan completo (Full)
    cmd = [sys.executable, str(BASE_DIR / "main.py"), "-t", target, "--full"]
    
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

def run_micro_scan(target: str, phases_to_run: list) -> dict:
    """
    Ejecuta un micro-scan: solo las fases específica que cambiaron.
    
    Args:
        target: Dominio a escanear
        phases_to_run: Lista de fases a ejecutar (recon, ports, urls, vulns)
    
    Returns:
        Dict con resultado del scan
    """
    if not phases_to_run or "full" in phases_to_run:
        log_sched(f"Ejecutando scan completo para: {target}", "info")
        return run_scan(target, diff_only=False)
    
    log_sched(f"MICRO-SCAN para {target}: ejecutando fases {phases_to_run}", "warn")
    
    # Construir comando con solo las fases necesarias
    cmd_parts = [sys.executable, str(BASE_DIR / "main.py"), "-t", target]
    
    for phase in phases_to_run:
        if phase == "recon":
            cmd_parts.append("--recon")
        elif phase == "ports":
            cmd_parts.append("--ports")
        elif phase == "urls":
            cmd_parts.append("--urls")
        elif phase == "vulns":
            cmd_parts.append("--vulns")
        elif phase == "diff":
            cmd_parts.append("--report")  # Solo generar reporte
    
    log_sched(f"  Comando: {' '.join(cmd_parts)}", "info")
    
    try:
        process = subprocess.Popen(
            cmd_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        for line in process.stdout:
            if any(m in line for m in ["[+]", "[!]", "[-]", "[>]", "[*]", "[D]"]):
                print(f"  {line.strip()}")
        
        process.wait()
        
        if process.returncode == 0:
            log_sched(f"Micro-scan completado: {target}", "success")
            return {"success": True, "phases_run": phases_to_run}
        else:
            log_sched(f"Error en micro-scan: {target} (code: {process.returncode})", "error")
            return {"success": False, "code": process.returncode}
            
    except Exception as e:
        log_sched(f"Error ejecutando micro-scan: {e}", "error")
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
    
    targets_file = ROOT_DIR / "config" / "targets.txt"
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
    p = argparse.ArgumentParser(description="BugBounty Scheduler 24/7 v2.0")
    p.add_argument("-t", "--target", help="Target específico")
    p.add_argument("-l", "--list", default=str(ROOT_DIR / "config" / "targets.txt"), help="Archivo de targets")
    p.add_argument("-i", "--interval", type=int, default=6, help="Intervalo en horas (default: 6)")
    p.add_argument("--watch", action="store_true", help="Modo watch (observar un target)")
    p.add_argument("--daemon", action="store_true", help="Modo daemon 24/7")
    p.add_argument("--diff", action="store_true", default=True, help="Solo escanear si hay cambios")
    p.add_argument("--full", action="store_true", help="Scan completo siempre")
    p.add_argument("--h1-new", action="store_true", help="Buscar programas nuevos en H1")
    p.add_argument("--micro-scan", action="store_true", default=True, help="Micro-scan focalizado (default: True)")
    p.add_argument("--no-micro-scan", action="store_false", dest="micro_scan", help="Desactivar micro-scan (ejecutar full scan)")
    args = p.parse_args()
    
    # Inicializar DB si está disponible
    if HAS_DB:
        init_db()
    
    if args.watch and args.target:
        run_watch_mode(args.target)
    elif args.daemon:
        run_scheduler_daemon(args.interval, diff_only=not args.full)
    elif args.h1_new:
        check_hackerone_new()
    elif args.target:
        run_scan(args.target, diff_only=not args.full, micro_scan=args.micro_scan)
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
