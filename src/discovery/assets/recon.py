"""
Módulo de Reconocimiento basado en Capacidades (OzyRecon Platform)
"""

from pathlib import Path
from src.utils import log, dedupe, write_lines
from src.core.tool_manager import tool_manager

# Importar proveedores para asegurar registro
import src.scanners.wrappers.subfinder
import src.scanners.wrappers.discovery_tools

def run_recon(target: str, out_dir: Path, args) -> dict:
    """
    Ejecuta el flujo de reconocimiento usando capacidades de la plataforma.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Capacidad: asset_discovery (corre todos los providers: subfinder, amass, etc)
    log(f"Iniciando capacidad: asset_discovery para {target}", "info")
    all_subs = tool_manager.run_capability("asset_discovery", target, all_providers=True, threads=args.threads)
    
    # 2. Deduplicar y normalizar
    all_subs = dedupe([s.lower().strip() for s in all_subs if target in s])
    if target not in all_subs: all_subs.append(target)
    
    merged_file = out_dir / "all_subdomains.txt"
    write_lines(all_subs, merged_file)
    log(f"Subdominios totales: {len(all_subs)}", "success")

    # 3. Capacidad: dns_resolution
    log("Iniciando capacidad: dns_resolution", "info")
    resolved_subs = tool_manager.run_capability("dns_resolution", str(merged_file), threads=args.threads)
    if not resolved_subs:
        log("Resolución DNS no disponible o sin resultados, usando lista original", "warn")
        resolved_subs = all_subs
    
    resolved_file = out_dir / "resolved.txt"
    write_lines(resolved_subs, resolved_file)

    # 4. Capacidad: live_detection
    log("Iniciando capacidad: live_detection", "info")
    live_hosts_raw = tool_manager.run_capability("live_detection", str(resolved_file), threads=args.threads)
    
    # Extraer URLs limpias
    live_hosts = dedupe([l.split()[0] for l in live_hosts_raw if l.startswith("http")])
    log(f"Hosts vivos detectados: {len(live_hosts)}", "success")

    if not live_hosts and resolved_subs:
        log("🛑 ALERTA OPSEC: 0 hosts vivos. Posible bloqueo de WAF.", "critical")

    # 5. Capacidad: template_scan (Takeovers)
    log("Buscando vulnerabilidades de Takeover (Capacidad: template_scan)", "info")
    hosts_takeover_file = out_dir / "hosts_takeover.txt"
    write_lines(live_hosts, hosts_takeover_file)
    
    takeovers = tool_manager.run_capability("template_scan", str(hosts_takeover_file), severity="critical", update=False)
    
    return {
        "all_subdomains": all_subs,
        "resolved":       resolved_subs,
        "live_hosts":     live_hosts,
        "takeovers":      takeovers,
        "out_dir":        str(out_dir),
    }
