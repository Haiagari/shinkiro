"""
Escaneo de Puertos basado en Capacidades
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

import uuid

from src.core.target_normalizer import extract_target_host, first_token
from src.events.bus import event_bus
from src.events.events import AssetDiscovered, FindingDetected, ScanCompleted
from src.utils import log, dedupe, save_json
from src.core.tool_manager import tool_manager
from src.core.config import config

TOP_PORTS = "80,443,8080,8443,8000,8888,3000,4000,5000,7000,9000,9090,9200,6379,27017,3306,5432,21,22,25,53,110,143,993,995"

MAX_WORKERS = 5


def _resolve_max_hosts(args: Any, context: dict, total_hosts: int) -> int:
    candidates = [
        context.get("max_hosts"),
        getattr(args, "max_hosts", None),
        config.get("ports.max_hosts_per_run"),
    ]
    for value in candidates:
        if isinstance(value, int) and value > 0:
            return min(value, total_hosts)
    return total_hosts


def _run_port_scan(host: str) -> list:
    try:
        res = tool_manager.run_capability("port_scan", host, ports=TOP_PORTS)
        return res or []
    except Exception as e:
        log(f"port_scan failed for {host}: {e}", "warning")
        return []


def _run_service_discovery(host: str, ports: str) -> Optional[Any]:
    try:
        return tool_manager.run_capability("service_discovery", host, ports=ports)
    except Exception as e:
        log(f"service_discovery failed for {host}: {e}", "warning")
        return None


def run_ports(hosts: list, out_dir: Path, args, context: Optional[dict] = None) -> dict:
    context = context or {}
    out_dir.mkdir(parents=True, exist_ok=True)

    clean_hosts = []
    for h in hosts:
        h = extract_target_host(first_token(h)) if h else ""
        if h:
            clean_hosts.append(h)
    clean_hosts = dedupe(clean_hosts)

    if not clean_hosts:
        return {"open_ports": [], "services": {}, "out_dir": str(out_dir)}

    max_hosts = _resolve_max_hosts(args, context, len(clean_hosts))
    selected_hosts = clean_hosts[:max_hosts]

    log(f"Escaneando puertos en {len(selected_hosts)} host(s)...", "info")

    # 1. Capacidad: port_scan (Naabu) — paralelo con ThreadPoolExecutor
    log("Iniciando capacidad: port_scan", "info")
    open_ports_results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(_run_port_scan, host): host for host in selected_hosts}
        for future in as_completed(future_map):
            open_ports_results.extend(future.result())

    log(f"Puertos abiertos encontrados: {len(open_ports_results)}", "success")

    # 2. Capacidad: service_discovery (Nmap) — solo hosts con puertos, en paralelo
    log("Iniciando capacidad: service_discovery", "info")
    services = {}
    unique_hosts = dedupe([r.host for r in open_ports_results])

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        for host in unique_hosts[:10]:
            host_ports = ",".join([str(r.port) for r in open_ports_results if r.host == host])
            if host_ports:
                future = executor.submit(_run_service_discovery, host, host_ports)
                future_map[future] = host

        for future in as_completed(future_map):
            host = future_map[future]
            srv_res = future.result()
            if srv_res:
                services[host] = srv_res

    results = {
        "open_ports": [f"{r.host}:{r.port}" for r in open_ports_results],
        "services": services,
        "out_dir": str(out_dir),
    }

    save_json(out_dir / "port_results.json", results)

    session_id = str(uuid.uuid4())
    for port_str in results["open_ports"]:
        host = port_str.split(":")[0]
        event_bus.publish(AssetDiscovered(domain=host, ip=extract_target_host(host)))
    for host, srv_list in services.items():
        for srv in (srv_list if isinstance(srv_list, list) else [srv_list]):
            title = getattr(srv, "service_name", None) or getattr(srv, "port", "unknown")
            event_bus.publish(FindingDetected(
                title=f"Service: {title}",
                severity="info",
                host=host,
                description=str(srv),
            ))
    event_bus.publish(ScanCompleted(
        target=",".join(selected_hosts),
        session_id=session_id,
        status="completed",
        summary={"open_ports": len(results["open_ports"]), "hosts": len(selected_hosts)},
    ))

    return results
