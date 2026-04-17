"""
Módulo de reconocimiento
Herramientas: subfinder, amass, assetfinder, dnsx, httpx
Paralelismo real con ThreadPoolExecutor
"""

import concurrent.futures
from pathlib import Path
from .utils import log, run_cmd, read_lines, write_lines, dedupe, check_tools

REQUIRED_TOOLS = ["subfinder", "amass", "assetfinder", "dnsx", "httpx"]


def _run_subfinder(target: str, out_dir: Path, threads: int) -> list:
    """Ejecuta subfinder."""
    sf_out = out_dir / "subfinder.txt"
    run_cmd(
        f"subfinder -d {target} -silent -all -o {sf_out} -t {threads}",
        timeout=300
    )
    return read_lines(sf_out)


def _run_assetfinder(target: str, out_dir: Path) -> list:
    """Ejecuta assetfinder."""
    af_out = out_dir / "assetfinder.txt"
    run_cmd(f"assetfinder --subs-only {target} > {af_out}", timeout=120)
    return read_lines(af_out)


def _run_amass(target: str, out_dir: Path) -> list:
    """Ejecuta amass (pasivo y rápido)."""
    am_out = out_dir / "amass.txt"
    # Modo pasivo estricto, sin resolución DNS pesada, timeout de 2 minutos
    run_cmd(
        f"amass enum -passive -timeout 2 -d {target} -o {am_out}",
        timeout=150
    )
    return read_lines(am_out)


def _run_crtsh(target: str, out_dir: Path) -> list:
    """Consulta crt.sh"""
    _, crt_output = run_cmd(
        f"curl -s 'https://crt.sh/?q=%25.{target}&output=json' | "
        f"python3 -c \"import sys,json; data=json.load(sys.stdin); "
        f"[print(e['name_value']) for e in data if 'name_value' in e]\" 2>/dev/null",
        timeout=60
    )
    crt_subs = [s.strip() for s in crt_output.splitlines() if target in s and "*" not in s]
    crt_out = out_dir / "crtsh.txt"
    write_lines(crt_out, crt_subs)
    return crt_subs


def run_recon(target: str, out_dir: Path, args) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    available = check_tools(REQUIRED_TOOLS)

    log(f"Herramientas disponibles: {[t for t,v in available.items() if v]}", "info")
    missing = [t for t, v in available.items() if not v]
    if missing:
        log(f"No encontradas (instálalas): {missing}", "warn")

    all_subs = []

    # ── EJECUCIÓN EN PARALELO ────────────────────────────────
    log("Ejecutando herramientas de recon en paralelo...", "info")
    
    tasks = []
    if available["subfinder"]:
        tasks.append(("subfinder", lambda: _run_subfinder(target, out_dir, args.threads)))
    if available["assetfinder"]:
        tasks.append(("assetfinder", lambda: _run_assetfinder(target, out_dir)))
    if available["amass"]:
        tasks.append(("amass", lambda: _run_amass(target, out_dir)))
    
    # crt.sh siempre corre (sin dependencias)
    tasks.append(("crt.sh", lambda: _run_crtsh(target, out_dir)))
    
    # Ejecutar todo en paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(task[1]): task[0] for task in tasks}
        for future in concurrent.futures.as_completed(futures):
            tool_name = futures[future]
            try:
                subs = future.result()
                log(f"  {tool_name} → {len(subs)} subdominios", "success")
                all_subs.extend(subs)
            except Exception as e:
                log(f"  {tool_name} falló: {e}", "warn")

    # Verificar cuáles corrieron
    for tool, _ in tasks:
        available[tool] = True  # Si llegó hasta aquí, corrió

    # ── Deduplicar ─────────────────────────────────────────────
    all_subs = dedupe([s.lower().strip() for s in all_subs if target in s])
    
    # Siempre incluimos el target base
    if target not in all_subs:
        all_subs.append(target)
    
    merged_out = out_dir / "all_subdomains.txt"
    write_lines(merged_out, all_subs)
    log(f"Total subdominios únicos: {len(all_subs)}", "success")

    # ── Resolución DNS con dnsx ────────────────────────────────
    resolved_subs = all_subs
    if available["dnsx"] and all_subs:
        log("Resolviendo DNS con dnsx...", "info")
        dns_out = out_dir / "resolved.txt"
        run_cmd(
            f"dnsx -l {merged_out} -silent -o {dns_out} -t {args.threads}",
            timeout=300
        )
        resolved_subs = read_lines(dns_out)
        if resolved_subs:
            log(f"  Subdominios con DNS válido: {len(resolved_subs)}", "success")
        else:
            log("  dnsx no devolvió resultados. Usando lista original como fallback.", "warn")
            resolved_subs = all_subs
    else:
        log("dnsx no disponible — usando todos los subdominios sin resolver", "warn")

    # ── Detección de hosts vivos con httpx ─────────────────────
    live_hosts = []
    if available["httpx"] and resolved_subs:
        log("Detectando hosts vivos con httpx (Modo Resiliente)...", "info")
        resolved_file = out_dir / "resolved.txt"
        if not resolved_file.exists():
            write_lines(resolved_file, resolved_subs)
        live_out = out_dir / "live_hosts.txt"
        
        # Agregamos: -retries 2 y bajamos threads a 30 para no saturar la red
        run_cmd(
            f"httpx -l {resolved_file} -silent -status-code -title -tech-detect "
            f"-retries 2 -threads 30 -timeout 15 -o {live_out}",
            timeout=600
        )
        live_hosts_raw = read_lines(live_out)
        live_hosts = dedupe([l.split()[0] for l in live_hosts_raw if l.startswith("http")])
        log(f"  Hosts vivos: {len(live_hosts)}", "success")
    else:
        log("httpx no disponible — hosts vivos no verificados", "warn")
        live_hosts = [f"https://{s}" for s in resolved_subs[:50]]

    # ── Takeover check con Nuclei (más preciso) ────────────────
    takeover_candidates = []
    
    # Método 1: Regex básico (rápido)
    takeover_patterns = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket",
        "The specified bucket does not exist",
        "herokucdn.com/error-pages/no-such-app",
        "This UserVoice subdomain is currently available",
        "is not a registered InCloud YouTrack",
        "Fastly error: unknown domain",
        "Sorry, We Couldn't Find That Page",
    ]
    for host in live_hosts:
        for pat in takeover_patterns:
            if pat.lower() in host.lower():
                takeover_candidates.append(host)
                break
    
    # Método 2: Nuclei takeover templates (más preciso)
    if available.get("nuclei") and live_hosts:
        log("Verificando takeovers con Nuclei (templates especializados)...", "info")
        
        hosts_file = out_dir / "hosts_takeover.txt"
        write_lines(hosts_file, [h.split()[0] for h in live_hosts[:50]])
        
        nuclei_takeover = out_dir / "nuclei_takeover.json"
        
        # Usar solo templates de takeover (descargarlos de: nuclei-templates)
        run_cmd(
            f"nuclei -l {hosts_file} -t takeover -o {nuclei_takeover} -json -silent",
            timeout=180
        )
        
        # Parsear resultados de nuclei
        takeover_lines = read_lines(nuclei_takeover)
        for line in takeover_lines:
            try:
                import json
                d = json.loads(line)
                url = d.get("matched-at", "")
                name = d.get("info", {}).get("name", "Takeover")
                
                takeover_candidates.append({
                    "url": url,
                    "type": name,
                    "source": "nuclei",
                    "severity": "critical",
                })
                log(f"  🔴 Takeover Nuclei: {name} -> {url[:50]}", "warn")
            except:
                continue
    
    # Deduplicar
    takeover_candidates = dedupe(takeover_candidates)
    
    if takeover_candidates:
        tc_out = out_dir / "takeover_candidates.txt"
        write_lines(tc_out, [t.get("url") if isinstance(t, dict) else t for t in takeover_candidates])
        log(f"  Posibles takeovers: {len(takeover_candidates)} → {tc_out}", "warn")

    return {
        "all_subdomains": all_subs,
        "resolved":       resolved_subs,
        "live_hosts":     live_hosts,
        "takeovers":      takeover_candidates,
        "out_dir":        str(out_dir),
    }
