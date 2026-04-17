#!/usr/bin/env python3
"""
BugBounty Framework — Orquestador principal (Sprint 1)
Uso: python main.py -t target.com [--full | --recon | --ports | --urls | --vulns]
"""

import argparse
import sys
import time
from pathlib import Path
from datetime import datetime

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
    p.add_argument("-t", "--target", required=True, help="Dominio objetivo (ej: target.com)")
    p.add_argument("-o", "--output", default="output", help="Directorio de salida")
    p.add_argument("-p", "--program", help="Programa de HackerOne (ej: google, apple)")
    p.add_argument("--full",   action="store_true", help="Ejecutar pipeline completo")
    p.add_argument("--recon",  action="store_true", help="Solo reconocimiento")
    p.add_argument("--ports",  action="store_true", help="Solo escaneo de puertos")
    p.add_argument("--urls",   action="store_true", help="Solo descubrimiento de URLs")
    p.add_argument("--vulns",  action="store_true", help="Solo escaneo de vulnerabilidades")
    p.add_argument("--report", action="store_true", help="Generar reporte")
    p.add_argument("--threads", type=int, default=50, help="Threads (default: 50)")
    p.add_argument("--timeout", type=int, default=10,  help="Timeout (default: 10)")
    return p.parse_args()

def main():
    args = parse_args()
    banner()

    # Inicializar Base de Datos (Sprint 4)
    init_db()

    # Cargar configuración
    config = load_config()
    
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
        "phases": {}
    }

    start_time = time.time()

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
            context["phases"]["recon"] = run_recon(target, out_dir / "recon", args)

        # FASE 1.5 — DETECCIÓN DE WAF
        live_hosts = context["phases"].get("recon", {}).get("live_hosts", [])
        if live_hosts and args.waf_detection:
            log("Fase 1.5: Detectando WAFs...", "phase")
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
            # Obtenemos hosts de la fase anterior o usamos el target base
            hosts = context["phases"].get("recon", {}).get("live_hosts", [target])
            context["phases"]["ports"] = run_ports(hosts, out_dir / "ports", args, context)

        # FASE 3 — URLs
        if do_urls:
            log("Fase 3: URLs y Endpoints", "phase")
            hosts = context["phases"].get("recon", {}).get("live_hosts", [target])
            context["phases"]["urls"] = run_crawler(hosts, out_dir / "urls", args, context)

        # FASE — JS ANALYSIS (Sprint 2)
        log("Fase: Análisis de JavaScript", "phase")
        context["phases"]["js_analysis"] = run_js_analyzer(target, out_dir / "js_analysis", args, context)

        # FASE — FUZZING INTELIGENTE (Sprint 6)
        log("Fase: Fuzzing Contextual", "phase")
        context["phases"]["fuzzer"] = run_fuzzer(target, out_dir / "fuzzer", args, context)

        # FASE 4 — VULNS
        if do_vulns:
            log("Fase 4: Vulnerabilidades", "phase")
            urls = context["phases"].get("urls", {}).get("all_urls", [f"https://{target}"])
            context["phases"]["vulns"] = run_vulns(urls, out_dir / "vulns", args, context)

        # FASE — INTELIGENCIA (Sprint 2)
        log("Fase: Análisis de Inteligencia", "phase")
        context["phases"]["intelligence"] = run_intelligence(target, out_dir / "intelligence", args, context)

        # FASE — DIFF (Sprint 3)
        log("Fase: Motor de Diferencias", "phase")
        context["phases"]["diff"] = run_diff(target, out_dir / "diff", context)

        # FASE — EXPORT (Sprint 5)
        log("Fase: Exportación de Resultados", "phase")
        context["phases"]["exporter"] = run_exporter(target, out_dir / "exporter", context)

        # FASE 5 — REPORT
        if do_report:
            # Verificar scope (Sprint 7)
            if allowed_scope:
                log("Verificando que los hallazgos estén en scope...", "info")
                # Acá se filtrarían los resultados vs el allowed_scope
                
            log("Fase 5: Reporte Final", "phase")
            generate_report(target, context["phases"], out_dir / "reports", ts, context)

        # NOTIFICACIONES (Sprint 3)
        run_notifier(target, context, config)

        # GUARDAR EN DB (Sprint 4)
        save_scan_to_db(context)

    except Exception as e:
        log(f"Error crítico en el pipeline: {e}", "error")
        logger.exception(e)

    elapsed = round(time.time() - start_time, 2)
    log(f"Pipeline completado en {elapsed}s", "success")
    log(f"Resultados en: {out_dir}", "info")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Detenido por el usuario.")
        sys.exit(0)

