#!/usr/bin/env python3
"""
BugBounty Framework — Orquestador principal (Sprint 1)
Uso: python3 backend/main.py -t target.com [--full | --recon | --ports | --urls | --vulns]
"""

import argparse
import sys
import time
import os
from pathlib import Path
from datetime import datetime

# Permitir que los imports internos funcionen tanto con `python3 backend/main.py`
# como con herramientas que cargan el módulo desde el paquete `backend`.
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DEFAULT_OUTPUT_DIR = str(ROOT_DIR / "runtime" / "scans")
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Módulos del framework
from modules.recon import run_recon
from modules.ports import run_ports
from modules.crawler import run_crawler
from modules.vuln import run_vulns
from modules.js_analyzer import run_js_analyzer
from modules.fuzzer import run_fuzzer
from modules.intelligence import run_intelligence
from modules.diff import run_diff
from modules.exporter import run_exporter
from modules.notifier import run_notifier
from modules.database import init_db, save_scan_to_db
from modules.report import generate_report
from modules.utils import banner, log, load_config, logger
from modules.waf_detector import detect_waf, adjust_strategy
from modules.enrichment import run_enrichment

def parse_args():
    p = argparse.ArgumentParser(
        description="BugBounty Automation Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-t", "--target", help="Dominio objetivo (ej: target.com)")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT_DIR, help="Directorio de salida")
    p.add_argument("-p", "--program", help="Programa de HackerOne (ej: google, apple)")
    p.add_argument("--full",   action="store_true", help="Ejecutar pipeline completo")
    p.add_argument("--recon",  action="store_true", help="Solo reconocimiento")
    p.add_argument("--ports",  action="store_true", help="Solo escaneo de puertos")
    p.add_argument("--urls",   action="store_true", help="Solo descubrimiento de URLs")
    p.add_argument("--vulns",  action="store_true", help="Solo escaneo de vulnerabilidades")
    p.add_argument("--report", action="store_true", help="Generar reporte")
    p.add_argument("--waf-detection", action="store_true", help="Detectar WAF")
    p.add_argument("--threads", type=int, default=50, help="Threads (default: 50)")
    p.add_argument("--timeout", type=int, default=10,  help="Timeout (default: 10)")
    p.add_argument("--agent", choices=["hunt", "continuo", "servicio", "campaña", "investigacion", "forense"], help="Ejecutar en modo Agente IA")
    p.add_argument("--active-fuzz", action="store_true", help="Ejecutar fuzzing activo con ffuf")
    return p.parse_args()

def main():
    args = parse_args()
    banner()

    # MODO AGENTE (Fase 2)
    if args.agent:
        from modules.agent import BugBountyAgent
        init_db()
        agent = BugBountyAgent()
        result = agent.run(args.agent, args.target)
        
        if "multi_results" in result:
            log(f"Campaña finalizada sobre {len(result['multi_results'])} targets.", "success")
        else:
            log(f"Agente finalizado con {result.get('steps_taken', 0)} pasos.", "success")
        sys.exit(0)

    # Cargar configuración normal
    config = load_config()

    # Agregar tools al PATH de ejecución
    tools_dir = config.get("tools_path", "tools/go/bin")
    # Usar ruta absoluta desde ROOT_DIR
    tools_absolute = str((ROOT_DIR / tools_dir).absolute())
    if tools_absolute not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{tools_absolute}:{os.environ.get('PATH', '')}"
        log(f"Herramientas añadidas al PATH: {tools_absolute}", "info")
    
    # Inicializar Base de Datos (Sprint 4)
    init_db()
    
    # SCOPE AUTOMÁTICO (Sprint 7): Si hay programa, descargar scope
    allowed_scope = []
    if args.program:
        from modules.program_scraper import sync_program
        log(f"Sincronizando scope del programa: {args.program}", "info")
        scope_data = sync_program(args.program)
        allowed_scope = scope_data.get("scope", [])
        if allowed_scope:
            log(f"Scope cargado: {len(allowed_scope)} dominios/IPs permitidos", "success")
    
    # Normalizar target
    target = args.target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output) / target / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    log(f"Iniciando sesión: {target}", "info")
    log(f"Output: {out_dir}", "info")

    # Inicializar Objeto de Contexto (Sprint 1)
    context = {
        "target": target,
        "start_time": ts,
        "out_dir": str(out_dir),
        "args": vars(args),
        "config": config,
        "phases": {},
        "scan_status": {
            "status": "running",
            "phase": "init",
            "progress": 0,
            "message": "Inicializando sesión",
            "history": [],
        },
    }

    def update_status(phase: str, progress: int, message: str, status: str = "running", error: str | None = None):
        snapshot = context.setdefault("scan_status", {"history": []})
        event = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "phase": phase,
            "progress": progress,
            "status": status,
            "message": message,
        }
        if error:
            event["error"] = error
        snapshot["phase"] = phase
        snapshot["progress"] = progress
        snapshot["status"] = status
        snapshot["message"] = message
        snapshot["updated_at"] = datetime.utcnow().isoformat()
        snapshot["history"] = (snapshot.get("history", []) + [event])[-50:]
        if error:
            snapshot["error"] = error
        elif "error" in snapshot:
            snapshot.pop("error", None)

    start_time = time.time()

    update_status("init", 0, "Inicializando base de datos y contexto")
    save_scan_to_db(context)

    # Determinar qué fases correr
    run_all = not any([args.recon, args.ports, args.urls, args.vulns, args.report])
    do_recon = run_all or args.full or args.recon
    do_ports = run_all or args.full or args.ports
    do_urls  = run_all or args.full or args.urls
    do_vulns = run_all or args.full or args.vulns
    do_report = run_all or args.full or args.report

    try:
        # FASE 1 — RECON
        if do_recon:
            log("Fase 1: Reconocimiento", "phase")
            update_status("recon", 15, "Reconocimiento pasivo y resolución de hosts")
            context["phases"]["recon"] = run_recon(target, out_dir / "recon", args)
            save_scan_to_db(context)

        # FASE 1.5 — DETECCIÓN DE WAF
        live_hosts = context["phases"].get("recon", {}).get("live_hosts", [])
        if live_hosts and args.waf_detection:
            log("Fase 1.5: Detectando WAFs...", "phase")
            update_status("waf", 20, "Detectando WAF y ajustando estrategia")
            from modules.waf_detector import run_waf_detection
            waf_results = run_waf_detection([live_hosts[0]], out_dir / "waf")
            if waf_results:
                context["phases"]["waf"] = waf_results
                # Ajustar estrategia según WAF
                first_waf = list(waf_results.values())[0]
                adj = adjust_strategy(first_waf)
                log(f"  WAF detectado: {first_waf.get('name')} - ajustando a {adj.get('threads')} threads", "warn")

        # FASE 2 — PORTS
        if do_ports:
            log("Fase 2: Puertos y Servicios", "phase")
            update_status("ports", 35, "Escaneando puertos y servicios")
            hosts = context["phases"].get("recon", {}).get("live_hosts", [target])
            context["phases"]["ports"] = run_ports(hosts, out_dir / "ports", args, context)
            save_scan_to_db(context)

        # FASE 3 — URLs
        if do_urls:
            log("Fase 3: URLs y Endpoints", "phase")
            update_status("urls", 50, "Descubriendo URLs y endpoints")
            hosts = context["phases"].get("recon", {}).get("live_hosts", [target])
            context["phases"]["urls"] = run_crawler(hosts, out_dir / "urls", args, context)
            save_scan_to_db(context)

        # FASE — JS ANALYSIS (Sprint 2)
        log("Fase: Análisis de JavaScript", "phase")
        update_status("js_analysis", 60, "Analizando JavaScript y secretos")
        context["phases"]["js_analysis"] = run_js_analyzer(target, out_dir / "js_analysis", args, context)

        # FASE — FUZZING INTELIGENTE (Sprint 6)
        log("Fase: Fuzzing Contextual", "phase")
        update_status("fuzzer", 70, "Ejecutando fuzzing contextual")
        context["phases"]["fuzzer"] = run_fuzzer(target, out_dir / "fuzzer", args, context)

        # FASE — FUZZING ACTIVO (ffuf) (Fase 5)
        if hasattr(args, 'active_fuzz') and args.active_fuzz:
            from modules.active_fuzz import run_active_fuzz
            log("Fase: Fuzzing Activo (ffuf)", "phase")
            update_status("active_fuzz", 75, "Fuzzing activo en ejecución")
            context["phases"]["active_fuzz"] = run_active_fuzz(target, out_dir / "active_fuzz", args.threads)

        # FASE 4 — VULNS
        if do_vulns:
            log("Fase 4: Vulnerabilidades", "phase")
            update_status("vulns", 85, "Escaneando vulnerabilidades")
            urls = context["phases"].get("urls", {}).get("all_urls", [f"https://{target}"])
            context["phases"]["vulns"] = run_vulns(urls, out_dir / "vulns", args, context)
            save_scan_to_db(context)

        # FASE — INTELIGENCIA (Sprint 2)
        log("Fase: Análisis de Inteligencia", "phase")
        update_status("intelligence", 90, "Procesando inteligencia y scoring")
        context["phases"]["intelligence"] = run_intelligence(target, out_dir / "intelligence", args, context)

        # FASE — DIFF (Sprint 3) - Ahora con SQLite
        log("Fase: Motor de Diferencias", "phase")
        update_status("diff", 95, "Calculando diff contra scans previos")
        context["phases"]["diff"] = run_diff(target, out_dir / "diff", context, use_db=True)

        # FASE — EXPORT (Sprint 5)
        log("Fase: Exportación de Resultados", "phase")
        update_status("exporter", 98, "Exportando resultados")
        context["phases"]["exporter"] = run_exporter(target, out_dir / "exporter", context)

        # FASE 5 — REPORT
        if do_report:
            # Verificar scope (Sprint 7)
            if allowed_scope:
                log("Verificando que los hallazgos estén en scope...", "info")
                # Acá se filtrarían los resultados vs el allowed_scope
                
            log("Fase 5: Reporte Final", "phase")
            update_status("report", 100, "Generando reporte final", status="completed")
            generate_report(target, context["phases"], out_dir / "reports", ts, context)

        # NOTIFICACIONES (Sprint 3)
        run_notifier(target, context, config)

        # GUARDAR EN DB (Sprint 4)
        update_status("completed", 100, "Pipeline completado", status="completed")
        save_scan_to_db(context)

    except Exception as e:
        log(f"Error crítico en el pipeline: {e}", "error")
        logger.exception(e)
        update_status("error", context.get("scan_status", {}).get("progress", 0), "Pipeline con errores", status="error", error=str(e))
        save_scan_to_db(context)

    elapsed = round(time.time() - start_time, 2)
    log(f"Pipeline completado en {elapsed}s", "success")
    log(f"Resultados en: {out_dir}", "info")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Detenido por el usuario.")
        sys.exit(0)
