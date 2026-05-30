"""
Módulo de Fuzzing Inteligente (Context-Aware)
Genera y ejecuta ataques basados en la tecnología detectada.
"""

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.core.target_normalizer import first_token, normalize_base_target
from src.utils import log, run_cmd, save_json, check_tools

ROOT_DIR = Path(__file__).resolve().parents[2]
WORDLIST_DIR = ROOT_DIR / "resources" / "wordlists"

REQUIRED_TOOLS = ["ffuf"]

# Mapeo de Tecnología -> Wordlist específica
TECH_WORDLISTS = {
    "php": ["php_files.txt", "laravel_env.txt"],
    "asp": ["asp_files.txt", "asp_config.txt"],
    "java": ["jsp_files.txt", "jboss.txt"],
    "api": ["api_endpoints.txt", "graphql.txt"],
    "wordpress": ["wp_plugins.txt", "wp_admin.txt", "wp_config.txt"],
    "laravel": ["laravel_env.txt", "laravel_routes.txt"],
    "django": ["django_admin.txt", "django_config.txt"],
    "rails": ["rails_routes.txt", "ruby_config.txt"],
    "node": ["nodejs.txt", "express_routes.txt"],
    "apache": ["apache_config.txt", "htaccess.txt"],
    "nginx": ["nginx_config.txt"],
    "git": ["git_common.txt", "git_exposed.txt"],
    "aws": ["aws_keys.txt", "s3_buckets.txt"],
    "graphql": ["graphql.txt"],
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
    
    # Pre-calcular todas las tareas de fuzzing necesarias
    fuzz_tasks = []

    for host_entry in live_hosts[:10]:  # Limitar para no eternizar
        host = normalize_base_target(first_token(host_entry))

        # Detectar qué wordlists aplicar
        active_wordlists = ["common.txt"]  # Siempre una base

        entry_lower = host_entry.lower()
        for tech, wlist in TECH_WORDLISTS.items():
            if tech in entry_lower:
                active_wordlists.extend(wlist)
                log(f"  Tecnología detectada: {tech.upper()} en {host} → usando {wlist}", "info")

        # Preparar tareas
        for wl in active_wordlists:
            wl_path = WORDLIST_DIR / wl
            if not wl_path.exists():
                continue
            fuzz_tasks.append((host, wl, wl_path))
            
    # Función worker para ejecución en paralelo
    def _run_single_fuzz(task_args):
        h, w, w_path = task_args
        ffuf_out = out_dir / f"{h.replace('://', '_').replace('/', '_')}_{w}.json"
        log(f"  [Worker] Fuzzing {h} con {w}...", "info")
        
        run_cmd(
            f"ffuf -u {h}/FUZZ -w {w_path} -mc 200,201,301,302,401,403,405 "
            f"-silent -t 30 -o {ffuf_out} -of json",
            timeout=300,
        )

        local_results = []
        if ffuf_out.exists():
            try:
                import json
                with open(ffuf_out) as f:
                    data = json.load(f)
                    for res in data.get("results", []):
                        local_results.append(
                            {
                                "url": res.get("url"),
                                "status": res.get("status"),
                                "content_length": res.get("length"),
                                "technology": w.split("_")[0],
                            }
                        )
            except (json.JSONDecodeError, OSError):
                pass
        return local_results

    # Ejecutar en paralelo con máximo 3 workers para no saturar la red local
    if fuzz_tasks:
        log(f"Ejecutando {len(fuzz_tasks)} tareas de fuzzing en paralelo...", "info")
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(_run_single_fuzz, task): task for task in fuzz_tasks}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        fuzz_results.extend(res)
                except Exception as e:
                    task = futures[future]
                    log(f"Error en worker de fuzzing para {task}: {e}", "error")

    save_json(out_dir / "results.json", {"fuzzing_findings": fuzz_results})
    log(
        f"Fuzzing inteligente completado: {len(fuzz_results)} rutas interesantes encontradas.",
        "success",
    )

    return {"findings": fuzz_results}
