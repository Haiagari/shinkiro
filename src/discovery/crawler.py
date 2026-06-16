from pathlib import Path
import hashlib

from src.core.providers.http_clients import http_client
from src.core.target_normalizer import first_token, extract_target_host, normalize_base_target
from src.utils import log, run_cmd, read_lines, dedupe, check_tools, save_json
from src.core.async_executor import async_executor

ROOT_DIR = Path(__file__).resolve().parents[2]

REQUIRED_TOOLS = ["waybackurls", "gau", "katana", "hakrawler", "ffuf"]

INTERESTING_EXTENSIONS = {
    ".js",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".env",
    ".bak",
    ".backup",
    ".old",
    ".sql",
    ".log",
    ".conf",
    ".config",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
}

INTERESTING_PARAMS = [
    "url",
    "redirect",
    "next",
    "return",
    "returnurl",
    "return_url",
    "file",
    "path",
    "page",
    "include",
    "doc",
    "document",
    "id",
    "uid",
    "user_id",
    "account",
    "key",
    "token",
    "api_key",
    "secret",
    "debug",
    "admin",
    "callback",
    "jsonp",
    "load",
    "fetch",
]


def run_crawler(hosts: list, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Fase 3: Descubrimiento de URLs, endpoints y archivos sensibles.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    available = check_tools(REQUIRED_TOOLS)

    # Normalizar hosts a URLs completas
    urls = []
    for h in hosts:
        h = first_token(h)
        urls.append(normalize_base_target(h))

    urls = dedupe(urls)

    if not urls:
        log("Sin hosts válidos para el descubrimiento de URLs", "warn")
        return {"all_urls": [], "interesting": [], "js_files": [], "out_dir": str(out_dir)}

    log(f"Descubriendo URLs en {len(urls)} host(s)...", "info")

    # Extraer dominio base para Wayback/GAU
    domains = dedupe([host for host in (extract_target_host(u) for u in urls) if host])

    # ── Parallel tool execution ────────────────────────────────
    tool_tasks = []

    if available["waybackurls"]:
        log("Consultando Wayback Machine...", "info")
        wb_out = out_dir / "wayback.txt"
        def _run_wayback(domains=domains[:5], wb_out=wb_out):
            for domain in domains:
                run_cmd(f"echo '{domain}' | waybackurls >> {wb_out}", timeout=120)
            return read_lines(wb_out)
        tool_tasks.append({'fn': _run_wayback, 'name': 'waybackurls', 'timeout': 120})
    else:
        log("waybackurls no disponible — saltando", "warn")

    if available["gau"]:
        log("Consultando fuentes con gau...", "info")
        gau_out = out_dir / "gau.txt"
        def _run_gau(domains=domains[:5], gau_out=gau_out):
            for domain in domains:
                run_cmd(f"gau --threads {args.threads} --o {gau_out} {domain}", timeout=180)
            return read_lines(gau_out)
        tool_tasks.append({'fn': _run_gau, 'name': 'gau', 'timeout': 180})
    else:
        log("gau no disponible — saltando", "warn")

    if available["katana"]:
        log("Crawl activo con katana...", "info")
        kata_out = out_dir / "katana.txt"
        def _run_katana(urls=urls[:10], kata_out=kata_out):
            for url in urls:
                run_cmd(
                    f"katana -u {url} -silent -d 3 -jc -kf all "
                    f"-c {args.threads} -timeout {args.timeout} -o {kata_out}",
                    timeout=300,
                )
            return read_lines(kata_out)
        tool_tasks.append({'fn': _run_katana, 'name': 'katana', 'timeout': 300})
    else:
        log("katana no disponible — saltando", "warn")

    if available["hakrawler"]:
        log("Crawl con hakrawler...", "info")
        hak_out = out_dir / "hakrawler.txt"
        def _run_hakrawler(urls_str="\n".join(urls[:20]), hak_out=hak_out):
            run_cmd(f"echo '{urls_str}' | hakrawler -d 2 -t {args.threads} >> {hak_out}", timeout=200)
            return read_lines(hak_out)
        tool_tasks.append({'fn': _run_hakrawler, 'name': 'hakrawler', 'timeout': 200})
    else:
        log("hakrawler no disponible — saltando", "warn")

    if available["ffuf"]:
        wordlist = ROOT_DIR / "resources" / "wordlists" / "common.txt"
        if wordlist.exists():
            log("Fuzzing de directorios con ffuf...", "info")
            ffuf_out = out_dir / "ffuf"
            def _run_ffuf(urls=urls[:5], ffuf_out=ffuf_out):
                ffuf_out.mkdir(exist_ok=True)
                for url in urls:
                    domain_safe = extract_target_host(url).replace(".", "_")
                    run_cmd(
                        f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,201,301,302,401,403 "
                        f"-t {args.threads} -timeout {args.timeout} -silent "
                        f"-o {ffuf_out}/{domain_safe}.json -of json",
                        timeout=300,
                    )
                return None
            tool_tasks.append({'fn': _run_ffuf, 'name': 'ffuf', 'timeout': 300})
        else:
            log("wordlist no encontrada (resources/wordlists/common.txt) — saltando ffuf", "warn")

    # Execute all tools in parallel
    tool_results = async_executor.run_parallel(tool_tasks)

    # Collect URL results
    all_urls = []
    for r in tool_results:
        if r['status'] == 'completed':
            if r['name'] == 'waybackurls':
                log(f"waybackurls → {len(r['result'] or [])} URLs", "success")
            elif r['name'] == 'gau':
                log(f"gau → {len(r['result'] or [])} URLs", "success")
            elif r['name'] == 'katana':
                log(f"katana → {len(r['result'] or [])} URLs", "success")
            elif r['name'] == 'hakrawler':
                log(f"hakrawler → {len(r['result'] or [])} URLs", "success")
            elif r['name'] == 'ffuf':
                log("ffuf → fuzzing completado", "success")

            if isinstance(r['result'], list):
                all_urls.extend(r['result'])
        else:
            log(f"{r['name']} falló: {r['error']}", "warn")

    # ── Deduplicar y clasificar ─────────────────────────────────
    all_urls = dedupe([first_token(u) for u in all_urls if first_token(u).startswith("http")])

    # Filtrar por extensiones e inyecciones interesantes
    interesting = [
        u
        for u in all_urls
        if any(u.lower().endswith(ext) for ext in INTERESTING_EXTENSIONS)
        or any(f"?{p}=" in u.lower() or f"&{p}=" in u.lower() for p in INTERESTING_PARAMS)
    ]

    # Separar JS files
    js_files = [u for u in all_urls if u.split("?")[0].lower().endswith(".js")]

    # ── Descargar archivos JS ───────────────────────────────
    js_dir = out_dir / "downloaded_js"
    js_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []

    if js_files:
        log(f"Descargando {len(js_files[:20])} archivos JS...", "info")
        for js_url in js_files[:20]:
            try:
                fname = hashlib.md5(js_url.encode()).hexdigest() + ".js"
                fpath = js_dir / fname

                r = http_client.get(js_url, timeout=15)
                if r.status_code == 200:
                    fpath.write_bytes(r.content)
                    downloaded.append(str(fpath))
            except Exception as e:
                log(f"  Error descargando {js_url[:30]}: {e}", "warn")

        if downloaded:
            log(f"  {len(downloaded)} archivos JS descargados en {js_dir}", "success")

    results = {
        "all_urls": all_urls,
        "interesting": interesting,
        "js_files": js_files,
        "downloaded_js": downloaded,
        "out_dir": str(out_dir),
    }

    # Persistencia JSON para Sprint 1
    save_json(out_dir / "results.json", results)

    log(f"Total URLs únicas: {len(all_urls)}", "success")
    log(f"URLs interesantes: {len(interesting)}", "success")
    log(f"Archivos JS: {len(js_files)}", "success")

    return results
