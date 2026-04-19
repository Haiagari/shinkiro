"""
Módulo de Fuzzing Inteligente (Context-Aware)
Genera y ejecuta ataques basados en la tecnología detectada.
"""

import os
from pathlib import Path
from .utils import log, run_cmd, read_lines, save_json, check_tools

ROOT_DIR = Path(__file__).resolve().parents[2]
WORDLIST_DIR = ROOT_DIR / "resources" / "wordlists"

REQUIRED_TOOLS = ["ffuf"]

# Mapeo de Tecnología -> Wordlist específica
TECH_WORDLISTS = {
    "php":       ["php_files.txt", "laravel_env.txt"],
    "asp":       ["asp_files.txt", "asp_config.txt"],
    "java":      ["jsp_files.txt", "jboss.txt"],
    "api":       ["api_endpoints.txt", "graphql.txt"],
    "wordpress": ["wp_plugins.txt", "wp_admin.txt", "wp_config.txt"],
    "laravel":   ["laravel_env.txt", "laravel_routes.txt"],
    "django":    ["django_admin.txt", "django_config.txt"],
    "rails":     ["rails_routes.txt", "ruby_config.txt"],
    "node":      ["nodejs.txt", "express_routes.txt"],
    "apache":    ["apache_config.txt", "htaccess.txt"],
    "nginx":     ["nginx_config.txt"],
    "git":       ["git_common.txt", "git_exposed.txt"],
    "aws":       ["aws_keys.txt", "s3_buckets.txt"],
    "graphql":   ["graphql.txt"],
}

# Parámetros por WAF
WAF_ADJUST = {
    "cloudflare": {"threads": 10, "delay": 1},
    "aws_waf": {"threads": 20, "delay": 1},
    "sucuri": {"threads": 30, "delay": 0},
}

def select_wordlists(tech: str) -> list:
    """
    Selecciona las wordlists correctas según tecnología.
    """
    tech_lower = tech.lower()
    wordlists = TECH_WORDLISTS.get(tech_lower, ["common.txt"])
    
    # También buscar por cualquier coincidencia parcial
    if not any(w in TECH_WORDLISTS for w in [tech_lower]):
        for t, wl in TECH_WORDLISTS.items():
            if t in tech_lower or tech_lower in t:
                wordlists.extend(wl if isinstance(wl, list) else [wl])
    
    # Deduplicar pero mantener orden
    seen = set()
    result = []
    for w in wordlists:
        if w not in seen:
            seen.add(w)
            result.append(w)
    
    return result

def adjust_for_waf(waf: dict) -> dict:
    """
    Ajusta parámetros de fuzzing según WAF detectado.
    """
    if not waf.get("detected"):
        return {"threads": 50, "delay": 0}
    
    waf_type = waf.get("type", "default")
    return WAF_ADJUST.get(waf_type, {"threads": 50, "delay": 0})

def run_fuzzer(target: str, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Ejecuta ffuf usando wordlists dinámicas según el contexto.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if not check_tools(["ffuf"])["ffuf"]:
        log("ffuf no instalado — saltando fuzzing inteligente", "warn")
        return {}

    log("Iniciando fuzzing inteligente basado en tecnología...", "info")
    
    # Obtener tecnologías detectadas (esto viene de httpx en la fase de recon)
    # httpx devuelve algo como "[nginx] [php 7.4]" en sus logs
    recon_data = context.get("phases", {}).get("recon", {})
    live_hosts = recon_data.get("live_hosts", [])
    
    fuzz_results = []

    for host_entry in live_hosts[:10]: # Limitar para no eternizar
        host = host_entry.split()[0]
        if not host.startswith("http"): host = f"https://{host}"
        
        # Detectar qué wordlists aplicar
        active_wordlists = ["common.txt"] # Siempre una base
        
        entry_lower = host_entry.lower()
        for tech, wlist in TECH_WORDLISTS.items():
            if tech in entry_lower:
                active_wordlists.append(wlist)
                log(f"  Tecnología detectada: {tech.upper()} en {host} → usando {wlist}", "info")

        # Ejecutar ffuf para cada wordlist activa
        for wl in active_wordlists:
            wl_path = WORDLIST_DIR / wl
            if not wl_path.exists():
                # Si no existe la específica, saltamos
                continue
                
            log(f"  Fuzzing {host} con {wl}...", "info")
            ffuf_out = out_dir / f"{host.replace('://', '_').replace('/', '_')}_{wl}.json"
            
            # Comando ffuf optimizado
            run_cmd(
                f"ffuf -u {host}/FUZZ -w {wl_path} -mc 200,201,301,302,401,403,405 "
                f"-silent -t 30 -o {ffuf_out} -of json",
                timeout=300
            )
            
            # Analizar resultados de ffuf
            if ffuf_out.exists():
                try:
                    import json
                    with open(ffuf_out) as f:
                        data = json.load(f)
                        for res in data.get("results", []):
                            fuzz_results.append({
                                "url": res.get("url"),
                                "status": res.get("status"),
                                "content_length": res.get("length"),
                                "technology": wl.split("_")[0]
                            })
                except:
                    continue

    save_json(out_dir / "results.json", {"fuzzing_findings": fuzz_results})
    log(f"Fuzzing inteligente completado: {len(fuzz_results)} rutas interesantes encontradas.", "success")
    
    return {"findings": fuzz_results}
