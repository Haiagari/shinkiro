"""
Escaneo de Puertos basado en Capacidades
"""

from pathlib import Path
from typing import Any, Optional
from src.utils import log, dedupe, save_json
from src.core.tool_manager import tool_manager
from src.core.config import config

# Asegurar registro de proveedores
import src.core.providers.naabu
import src.core.providers.nmap

TOP_PORTS = "80,443,8080,8443,8000,8888,3000,4000,5000,7000,9000,9090,9200,6379,27017,3306,5432,21,22,25,53,110,143,993,995"

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


def run_ports(hosts: list, out_dir: Path, args, context: Optional[dict] = None) -> dict:
    context = context or {}
    out_dir.mkdir(parents=True, exist_ok=True)
    
    clean_hosts = []
    for h in hosts:
        h = h.split()[0] if h else ""
        h = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if h: clean_hosts.append(h)
    clean_hosts = dedupe(clean_hosts)

    if not clean_hosts:
        return {"open_ports": [], "services": {}, "out_dir": str(out_dir)}

    max_hosts = _resolve_max_hosts(args, context, len(clean_hosts))
    selected_hosts = clean_hosts[:max_hosts]

    log(f"Escaneando puertos en {len(selected_hosts)} host(s)...", "info")
    
    # 1. Capacidad: port_scan (Ej: Naabu)
    log("Iniciando capacidad: port_scan", "info")
    open_ports_results = []
    for host in selected_hosts:
        res = tool_manager.run_capability("port_scan", host, ports=TOP_PORTS)
        if res: open_ports_results.extend(res)

    log(f"Puertos abiertos encontrados: {len(open_ports_results)}", "success")

    # 2. Capacidad: service_discovery (Ej: Nmap)
    # Profundizar en los puertos encontrados
    log("Iniciando capacidad: service_discovery", "info")
    services = {}
    unique_hosts = dedupe([r.host for r in open_ports_results])
    
    for host in unique_hosts[:10]:
        # Filtrar puertos de este host
        host_ports = ",".join([str(r.port) for r in open_ports_results if r.host == host])
        if host_ports:
            srv_res = tool_manager.run_capability("service_discovery", host, ports=host_ports)
            if srv_res:
                services[host] = srv_res

    results = {
        "open_ports": [f"{r.host}:{r.port}" for r in open_ports_results],
        "services": services,
        "out_dir": str(out_dir)
    }
    
    save_json(out_dir / "port_results.json", results)
    return results
