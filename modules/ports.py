from pathlib import Path
from .utils import log, run_cmd, read_lines, write_lines, dedupe, check_tools, save_json

REQUIRED_TOOLS = ["naabu", "nmap", "masscan"]

TOP_PORTS = "80,443,8080,8443,8000,8888,3000,4000,5000,7000,9000,9090,9200,6379,27017,3306,5432,21,22,25,53,110,143,993,995"


def run_ports(hosts: list, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Fase 2: Escaneo de puertos y detección de servicios.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    available = check_tools(REQUIRED_TOOLS)

    # Extraer IPs/dominios limpios
    clean_hosts = []
    for h in hosts:
        # httpx puede agregar metadata (ej: [200] [nginx]), nos quedamos con la URL/Host
        h = h.split()[0] if h else ""
        h = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if h:
            clean_hosts.append(h)
    
    clean_hosts = dedupe(clean_hosts)

    if not clean_hosts:
        log("Sin hosts válidos para escanear puertos", "warn")
        return {"open_ports": [], "services": {}, "out_dir": str(out_dir)}

    hosts_file = out_dir / "hosts_to_scan.txt"
    write_lines(hosts_file, clean_hosts)
    log(f"Escaneando puertos en {len(clean_hosts)} host(s)...", "info")

    open_ports = []
    services   = {}

    # ── naabu (rápido, Go) ─────────────────────────────────────
    if available["naabu"]:
        log("Escaneo rápido con naabu...", "info")
        naabu_out = out_dir / "naabu.txt"
        run_cmd(
            f"naabu -l {hosts_file} -p {TOP_PORTS} -silent "
            f"-rate 500 -o {naabu_out} -timeout {args.timeout}",
            timeout=300
        )
        lines = read_lines(naabu_out)
        open_ports.extend(lines)
        log(f"naabu → {len(lines)} puertos abiertos", "success")
    else:
        log("naabu no disponible — saltando escaneo rápido", "warn")

    # ── nmap para detección de servicios/versiones ─────────────
    if available["nmap"] and open_ports:
        log("Detección de servicios con nmap...", "info")
        # Extraer IPs únicas de resultados naabu (formato host:port)
        unique_hosts = dedupe([p.split(":")[0] for p in open_ports if ":" in p])
        unique_ports = dedupe([p.split(":")[1] for p in open_ports if ":" in p])
        
        ports_str = ",".join(unique_ports) if unique_ports else TOP_PORTS
        # Limitamos hosts para no explotar el tiempo de escaneo
        targets_str = " ".join(unique_hosts[:50]) 

        nmap_out = out_dir / "nmap_services.txt"
        run_cmd(
            f"nmap -sV -sC --open -p {ports_str} {targets_str} "
            f"-oN {nmap_out} --host-timeout 60s -T4",
            timeout=900
        )
        nmap_lines = read_lines(nmap_out)
        for line in nmap_lines:
            if "open" in line and "/" in line:
                service_info = line.strip()
                port_proto = service_info.split()[0]
                services[port_proto] = service_info

        log(f"nmap → {len(services)} servicios identificados", "success")
    
    elif available["nmap"] and not open_ports and available["naabu"]:
        log("No se encontraron puertos abiertos con naabu", "info")
    
    elif available["nmap"]:
        # Fallback si naabu no está pero nmap sí
        log("Escaneo directo con nmap (fallback)...", "info")
        nmap_out = out_dir / "nmap_direct.txt"
        target_list = " ".join(clean_hosts[:15])
        run_cmd(
            f"nmap -sV --open -p {TOP_PORTS} {target_list} -oN {nmap_out} -T4",
            timeout=600
        )
        # (Lógica simplificada para el fallback)

    results = {
        "open_ports":  open_ports,
        "services":    services,
        "hosts_count": len(clean_hosts),
        "out_dir":     str(out_dir),
    }

    # Persistencia JSON para Sprint 1
    save_json(out_dir / "results.json", results)

    log(f"Total puertos abiertos: {len(open_ports)}", "success")
    return results

