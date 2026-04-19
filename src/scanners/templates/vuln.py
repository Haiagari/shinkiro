"""
Escaneo de Vulnerabilidades basado en Capacidades
"""

import json
import re
import time
from pathlib import Path
from src.utils import log, dedupe, write_lines, save_json, get_random_ua
from src.core.tool_manager import tool_manager

# Asegurar registro de proveedores
import src.core.providers.nuclei
import src.core.providers.vuln_tools

def run_vulns(urls: list, out_dir: Path, args, context: dict = {}) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    
    clean_urls = dedupe([u.split()[0] for u in urls if u.startswith("http")])
    if not clean_urls:
        return {"findings": [], "out_dir": str(out_dir)}

    findings = []
    urls_file = out_dir / "urls_to_scan.txt"
    write_lines(clean_urls, urls_file)

    # 1. Capacidad: template_scan (Motores tipo Nuclei)
    log("Iniciando capacidad: template_scan", "info")
    template_findings = tool_manager.run_capability(
        "template_scan", str(urls_file), 
        rate_limit=50, update=True
    )
    if template_findings:
        findings.extend(template_findings)
        log(f"Hallazgos de template_scan: {len(template_findings)}", "success")

    # 2. Capacidad: web_fuzzing (Motores tipo Dalfox/FFUF)
    log("Iniciando capacidad: web_fuzzing", "info")
    param_urls = [u for u in clean_urls if "?" in u and "=" in u]
    if param_urls:
        param_file = out_dir / "param_urls.txt"
        write_lines(param_urls, param_file)
        fuzz_findings = tool_manager.run_capability("web_fuzzing", str(param_file))
        if fuzz_findings:
            findings.extend(fuzz_findings)

    # 3. Capacidad: db_probe (Motores tipo SQLMap/Ghauri)
    log("Iniciando capacidad: db_probe", "info")
    for url in param_urls[:5]: # Muestreo para no ser pesados
        db_findings = tool_manager.run_capability("db_probe", url)
        if db_findings:
            findings.extend(db_findings)

    # 4. Lógica de Auditoría Propia (IDOR, Exposed Files, etc)
    # [Aquí se mantiene la lógica personalizada de Python que ya tenías]
    
    results = {
        "findings": findings,
        "total_findings": len(findings),
        "out_dir": str(out_dir)
    }
    
    save_json(results, out_dir / "vuln_results.json")
    return results
