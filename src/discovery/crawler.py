from pathlib import Path
from urllib.parse import urlparse
from src.utils import log, run_cmd, read_lines, write_lines, dedupe, check_tools, save_json

ROOT_DIR = Path(__file__).resolve().parents[2]

REQUIRED_TOOLS = ["waybackurls", "gau", "katana", "hakrawler", "ffuf"]

INTERESTING_EXTENSIONS = {
    ".js", ".json", ".xml", ".yaml", ".yml", ".env",
    ".bak", ".backup", ".old", ".sql", ".log", ".conf", ".config",
    ".php", ".asp", ".aspx", ".jsp"
}

INTERESTING_PARAMS = [
    "url", "redirect", "next", "return", "returnurl", "return_url",
    "file", "path", "page", "include", "doc", "document", "id",
    "uid", "user_id", "account", "key", "token", "api_key", "secret",
    "debug", "admin", "callback", "jsonp", "load", "fetch",
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
        h = h.split()[0] if h else ""
        if not h.startswith("http"):
            h = f"https://{h}"
        urls.append(h.split("?")[0].rstrip("/"))
    
    urls = dedupe(urls)

    if not urls:
        log("Sin hosts válidos para el descubrimiento de URLs", "warn")
        return {"all_urls": [], "interesting": [], "js_files": [], "out_dir": str(out_dir)}

    log(f"Descubriendo URLs en {len(urls)} host(s)...", "info")

    # Extraer dominio base para Wayback/GAU
    domains = dedupe([urlparse(u).netloc for u in urls])
    all_urls = []

    # ── Wayback Machine ────────────────────────────────────────
    if available["waybackurls"]:
        log("Consultando Wayback Machine...", "info")
        wb_out = out_dir / "wayback.txt"
        for domain in domains[:5]:
            run_cmd(f"echo '{domain}' | waybackurls >> {wb_out}", timeout=120)
        wb_urls = read_lines(wb_out)
        log(f"waybackurls → {len(wb_urls)} URLs", "success")
        all_urls.extend(wb_urls)
    else:
        log("waybackurls no disponible — saltando", "warn")

    # ── GAU (getallurls) ────────────────────────────────────────
    if available["gau"]:
        log("Consultando fuentes con gau...", "info")
        gau_out = out_dir / "gau.txt"
        for domain in domains[:5]:
            run_cmd(
                f"gau --threads {args.threads} --o {gau_out} {domain}",
                timeout=180
            )
        gau_urls = read_lines(gau_out)
        log(f"gau → {len(gau_urls)} URLs", "success")
        all_urls.extend(gau_urls)
    else:
        log("gau no disponible — saltando", "warn")

    # ── Katana (crawler activo) ─────────────────────────────────
    if available["katana"]:
        log("Crawl activo con katana...", "info")
        kata_out = out_dir / "katana.txt"
        for url in urls[:10]:
            run_cmd(
                f"katana -u {url} -silent -d 3 -jc -kf all "
                f"-c {args.threads} -timeout {args.timeout} -o {kata_out}",
                timeout=300
            )
        kata_urls = read_lines(kata_out)
        log(f"katana → {len(kata_urls)} URLs", "success")
        all_urls.extend(kata_urls)
    else:
        log("katana no disponible — saltando", "warn")

    # ── hakrawler ──────────────────────────────────────────────
    if available["hakrawler"]:
        log("Crawl con hakrawler...", "info")
        hak_out = out_dir / "hakrawler.txt"
        urls_str = "\n".join(urls[:20])
        run_cmd(
            f"echo '{urls_str}' | hakrawler -d 2 -t {args.threads} >> {hak_out}",
            timeout=200
        )
        hak_urls = read_lines(hak_out)
        log(f"hakrawler → {len(hak_urls)} URLs", "success")
        all_urls.extend(hak_urls)
    else:
        log("hakrawler no disponible — saltando", "warn")

    # ── ffuf para fuzzing de directorios ──────────────────────
    if available["ffuf"]:
        log("Fuzzing de directorios con ffuf...", "info")
        wordlist = ROOT_DIR / "resources" / "wordlists" / "common.txt"
        if wordlist.exists():
            ffuf_out = out_dir / "ffuf"
            ffuf_out.mkdir(exist_ok=True)
            for url in urls[:5]:
                domain_safe = urlparse(url).netloc.replace(".", "_")
                run_cmd(
                    f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,201,301,302,401,403 "
                    f"-t {args.threads} -timeout {args.timeout} -silent "
                    f"-o {ffuf_out}/{domain_safe}.json -of json",
                    timeout=300
                )
            log("ffuf → fuzzing completado", "success")
        else:
            log("wordlist no encontrada (resources/wordlists/common.txt) — saltando ffuf", "warn")

    # ── Deduplicar y clasificar ─────────────────────────────────
    all_urls = dedupe([u.strip() for u in all_urls if u.startswith("http")])
    
    # Filtrar por extensiones e inyecciones interesantes
    interesting = [
        u for u in all_urls
        if any(u.lower().endswith(ext) for ext in INTERESTING_EXTENSIONS)
        or any(f"?{p}=" in u.lower() or f"&{p}=" in u.lower() for p in INTERESTING_PARAMS)
    ]
    
    # Separar JS files
    js_files = [u for u in all_urls if u.split("?")[0].lower().endswith(".js")]

    # ── Descargar archivos JS ───────────────────────────────
    js_dir = out_dir / "downloaded_js"
    downloaded = []
    
    if js_files:
        log(f"Descargando {len(js_files[:20])} archivos JS...", "info")
        
        import requests
        import hashlib
        
        for js_url in js_files[:20]:
            try:
                fname = hashlib.md5(js_url.encode()).hexdigest() + ".js"
                fpath = js_dir / fname
                
                r = requests.get(js_url, timeout=15, verify=False)
                if r.status_code == 200:
                    fpath.write_bytes(r.content)
                    downloaded.append(str(fpath))
            except Exception as e:
                log(f"  Error descargando {js_url[:30]}: {e}", "warn")
        
        if downloaded:
            log(f"  {len(downloaded)} archivos JS descargados en {js_dir}", "success")

    results = {
        "all_urls":    all_urls,
        "interesting": interesting,
        "js_files":    js_files,
        "downloaded_js": downloaded,
        "out_dir":     str(out_dir),
    }

    # Persistencia JSON para Sprint 1
    save_json(out_dir / "results.json", results)

    log(f"Total URLs únicas: {len(all_urls)}", "success")
    log(f"URLs interesantes: {len(interesting)}", "success")
    log(f"Archivos JS: {len(js_files)}", "success")

    return results
