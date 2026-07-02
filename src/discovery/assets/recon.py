"""
Módulo de Reconocimiento basado en Capacidades (PromptWall Platform)
"""

import uuid
from pathlib import Path

from src.core.target_normalizer import first_token, normalize_base_target
from src.events.bus import event_bus
from src.events.events import AssetDiscovered, FindingDetected, ScanCompleted
from src.plugins.hooks import dispatch_hook
from src.scope import in_scope
from src.utils import log, dedupe, write_lines
from src.core.tool_manager import tool_manager
from src.core.async_executor import async_executor

# Importar proveedores para asegurar registro


def run_recon(target: str, out_dir: Path, args) -> dict:
    """
    Ejecuta el flujo de reconocimiento usando capacidades de la plataforma.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Capacidad: asset_discovery (corre todos los providers en paralelo)
    log(f"Iniciando capacidad: asset_discovery para {target}", "info")
    results = async_executor.run_capability_parallel(
        tool_manager, "asset_discovery", [target],
        all_providers=True, threads=args.threads,
    )
    all_subs = results[0]['result'] if results and results[0]['status'] == 'completed' else []

    # 2. Deduplicar y normalizar
    target_lower = target.lower()
    all_subs = dedupe(
        [s.lower().strip() for s in all_subs if isinstance(s, str) and in_scope(s, target_lower)]
    )
    if target_lower not in all_subs:
        all_subs.append(target_lower)

    merged_file = out_dir / "all_subdomains.txt"
    write_lines(all_subs, merged_file)
    log(f"Subdominios totales: {len(all_subs)}", "success")

    # 3. Capacidad: dns_resolution
    log("Iniciando capacidad: dns_resolution", "info")
    resolved_subs = (
        tool_manager.run_capability("dns_resolution", str(merged_file), threads=args.threads) or []
    )
    if not resolved_subs:
        log("Resolución DNS no disponible o sin resultados, usando lista original", "warn")
        resolved_subs = all_subs

    resolved_file = out_dir / "resolved.txt"
    write_lines(resolved_subs, resolved_file)

    # 4. Capacidad: live_detection
    log("Iniciando capacidad: live_detection", "info")
    live_hosts_raw = (
        tool_manager.run_capability("live_detection", str(resolved_file), threads=args.threads)
        or []
    )

    # Extraer URLs limpias
    live_hosts = dedupe(
        [
            normalize_base_target(first_token(host))
            for host in live_hosts_raw
            if isinstance(host, str) and first_token(host).startswith("http")
        ]
    )
    log(f"Hosts vivos detectados: {len(live_hosts)}", "success")

    if not live_hosts and resolved_subs:
        log("🛑 ALERTA OPSEC: 0 hosts vivos. Posible bloqueo de WAF.", "critical")

    # 5. Capacidad: template_scan (Takeovers)
    log("Buscando vulnerabilidades de Takeover (Capacidad: template_scan)", "info")
    hosts_takeover_file = out_dir / "hosts_takeover.txt"
    write_lines(live_hosts, hosts_takeover_file)

    takeovers = (
        tool_manager.run_capability(
            "template_scan", str(hosts_takeover_file), severity="critical", update=False
        )
        or []
    )

    session_id = str(uuid.uuid4())
    for sub in all_subs:
        event_bus.publish(AssetDiscovered(domain=sub))
        dispatch_hook("asset_discovered", {"domain": sub})
    for host in live_hosts:
        event_bus.publish(AssetDiscovered(domain=host, ip=first_token(host) if "://" in host else None))
        dispatch_hook("asset_discovered", {"domain": host, "ip": first_token(host) if "://" in host else None})
    for to in (takeovers or []):
        title = to.get("title", to.get("name", "Takeover")) if isinstance(to, dict) else str(to)
        event_bus.publish(FindingDetected(
            title=title, severity="high", host=target, description=str(to),
        ))
        dispatch_hook("finding_detected", {
            "title": title, "severity": "high", "host": target, "description": str(to),
        })
    event_bus.publish(ScanCompleted(
        target=target,
        session_id=session_id,
        status="completed",
        summary={
            "subdomains": len(all_subs), "resolved": len(resolved_subs),
            "live_hosts": len(live_hosts), "takeovers": len(takeovers or []),
        },
    ))
    dispatch_hook("scan_complete", {
        "target": target, "session_id": session_id, "status": "completed",
        "summary": {
            "subdomains": len(all_subs), "resolved": len(resolved_subs),
            "live_hosts": len(live_hosts), "takeovers": len(takeovers or []),
        },
    })

    return {
        "all_subdomains": all_subs,
        "resolved": resolved_subs,
        "live_hosts": live_hosts,
        "takeovers": takeovers,
        "out_dir": str(out_dir),
    }
