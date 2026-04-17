import json
import re
from pathlib import Path
from .utils import log, run_cmd, read_lines, write_lines, dedupe, check_tools, save_json, get_stealth_headers, get_random_ua
from .rate_limiter import wait_if_needed, record_request, can_request
import time

REQUIRED_TOOLS = ["nuclei", "dalfox", "sqlmap", "ghauri", "curl"]

EXPOSED_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/wp-config.php",
    "/config.php", "/database.yml", "/.aws/credentials",
    "/server-status", "/phpinfo.php", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
    "/v1/api-docs", "/api/v1/users", "/admin", "/administrator",
    "/backup.zip", "/backup.tar.gz", "/dump.sql",
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Patrones para detectar IDOR automáticamente
IDOR_PARAM_PATTERNS = [
    r"[\?&]id=\d+",
    r"[\?&]user_id=\d+",
    r"[\?&]account_id=\d+",
    r"[\?&]order_id=\d+",
    r"[\?&]uid=\d+",
    r"[\?&]post_id=\d+",
    r"[\?&]comment_id=\d+",
    r"[\?&]invoice_id=\d+",
    r"[\?&]transaction_id=\d+",
]

IDOR_PATH_PATTERNS = [
    r"/api/v\d+/users/\d+",
    r"/api/v\d+/accounts/\d+",
    r"/api/v\d+/orders/\d+",
    r"/api/v\d+/profile",
    r"/users/\d+",
    r"/account/\d+",
    r"/orders/\d+",
    r"/profile/\d+",
]


def detect_idor_candidates(urls: list) -> list:
    """
    Detecta URLs con potencial IDOR y genera PoC automáticamente.
    """
    import re
    candidates = []
    
    for url in urls:
        # Buscar en query params
        for pattern in IDOR_PARAM_PATTERNS:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                param = match.group(0)
                # Generar PoC: cambiar el valor numérico
                base_value = re.search(r"\d+", param).group(0)
                poc_url = url.replace(base_value, str(int(base_value) + 1))
                
                candidates.append({
                    "url": url,
                    "poc_url": poc_url,
                    "param": param,
                    "type": "IDOR_CANDIDATE",
                    "severity": "high",
                    "poc": f"# IDOR PoC - cambiar user_id:\ncurl -X GET '{poc_url}'",
                })
                break
        
        # Buscar en path
        if not any(c["url"] == url for c in candidates):
            for pattern in IDOR_PATH_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    # Generar PoC
                    new_path = re.sub(r"/\d+", "/999999", url)
                    candidates.append({
                        "url": url,
                        "poc_url": new_path,
                        "param": "PATH_ID",
                        "type": "IDOR_CANDIDATE",
                        "severity": "high",
                        "poc": f"# IDOR PoC:\ncurl -X GET '{new_path}'",
                    })
                    break
    
    return candidates


def verify_idor(poc_url: str, original_url: str) -> dict:
    """
    Verifica si un IDOR es explotable (prueba básica).
    Enhanced: OPSEC headers y RateLimiter.
    """
    import requests
    import time
    
    # 1. Esperar si el rate limit lo pide (OPSEC)
    wait_if_needed()
    
    # 2. Usar headers de sigilo
    headers = get_stealth_headers()
    
    try:
        start = time.time()
        # Request original (para comparar)
        r1 = requests.get(original_url, headers=headers, timeout=10, verify=False)
        original_status = r1.status_code
        original_len = len(r1.text)
        
        # Registrar en el rate limiter
        ms = (time.time() - start) * 1000
        record_request(ms, original_status)

        # Volver a esperar para el segundo request
        wait_if_needed()
        
        start = time.time()
        # Request PoC (con ID modificado)
        r2 = requests.get(poc_url, headers=headers, timeout=10, verify=False)
        poc_status = r2.status_code
        poc_len = len(r2.text)
        
        # Registrar en el rate limiter
        ms = (time.time() - start) * 1000
        record_request(ms, poc_status)
        
        # Verificar diferencias que indican IDOR
        if poc_status != original_status:
            return {
                "exploitable": True,
                "reason": f"Status diferente: {original_status} vs {poc_status}",
                "confidence": "HIGH",
            }
        if abs(poc_len - original_len) > 100:
            return {
                "exploitable": True,
                "reason": f"Tamaño de respuesta diferente: {original_len} vs {poc_len}",
                "confidence": "MEDIUM",
            }
        
        return {
            "exploitable": False,
            "reason": "Sin diferencias detectadas",
            "confidence": "LOW",
        }
    except Exception as e:
        return {
            "exploitable": False,
            "reason": str(e),
            "confidence": "UNKNOWN",
        }


def run_vulns(urls: list, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Fase 4: Escaneo de vulnerabilidades y misconfigurations.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    available = check_tools(REQUIRED_TOOLS)

    clean_urls = dedupe([u.split()[0] for u in urls if u.startswith("http")])
    if not clean_urls:
        log("Sin URLs válidas para escanear vulnerabilidades", "warn")
        return {"findings": [], "out_dir": str(out_dir)}

    log(f"Escaneando {len(clean_urls)} URL(s) en busca de vulnerabilidades...", "info")
    findings = []
    urls_file = out_dir / "urls_to_scan.txt"
    write_lines(urls_file, clean_urls)

    # ── Nuclei (motor principal) ──────────────────────────────
    if available["nuclei"]:
        log("Actualizando templates de nuclei...", "info")
        run_cmd("nuclei -update-templates -silent", timeout=60)

        log("Escaneando con nuclei (severidad Media+ y Custom Templates)...", "info")
        nuclei_out = out_dir / "nuclei.json"
        custom_templates = Path(__file__).parent.parent / "custom_templates"
        
        # Comando de nuclei incluyendo templates personalizados
        cmd = (
            f"nuclei -l {urls_file} -severity critical,high,medium "
            f"-t {custom_templates} " # Incluir nuestros templates ninjas
            f"-o {nuclei_out} -json -silent -rate-limit 50 "
            f"-timeout {args.timeout} -bulk-size {args.threads}"
        )
        run_cmd(cmd, timeout=1200)
        nuclei_lines = read_lines(nuclei_out)
        for line in nuclei_lines:
            try:
                d = json.loads(line)
                findings.append({
                    "type":     "nuclei",
                    "severity": d.get("info", {}).get("severity", "unknown"),
                    "name":     d.get("info", {}).get("name", ""),
                    "url":      d.get("matched-at", ""),
                    "template": d.get("template-id", ""),
                })
            except:
                continue
        log(f"nuclei → {len(nuclei_lines)} hallazgos", "success")
    else:
        log("nuclei no disponible — saltando escaneo principal", "warn")

    # ── Dalfox (XSS especializado) ─────────────────────────────
    if available["dalfox"]:
        log("Escaneo XSS con dalfox...", "info")
        param_urls = [u for u in clean_urls if "?" in u and "=" in u]
        if param_urls:
            param_file = out_dir / "param_urls.txt"
            write_lines(param_file, param_urls[:50])
            dalfox_out = out_dir / "dalfox.txt"
            run_cmd(
                f"dalfox file {param_file} --silence --no-color "
                f"--worker {args.threads} --timeout {args.timeout} "
                f"-o {dalfox_out}",
                timeout=600
            )
            dalfox_results = read_lines(dalfox_out)
            for r in dalfox_results:
                if "[V]" in r or "[G]" in r:
                    findings.append({"type": "xss", "severity": "high", "raw": r})
            log(f"dalfox → {len(dalfox_results)} hallazgos potenciales", "success")
    
    # ── SQLmap / Ghauri (SQLi) ─────────────────────────────────
    sql_tool = "ghauri" if available["ghauri"] else ("sqlmap" if available["sqlmap"] else None)
    if sql_tool:
        log(f"Escaneo SQLi con {sql_tool}...", "info")
        param_urls = [u for u in clean_urls if "?" in u and "=" in u][:10]
        for url in param_urls:
            cmd = f"ghauri -u '{url}' --level 1 --batch --output-dir {out_dir}/ghauri" if sql_tool == "ghauri" else \
                  f"sqlmap -u '{url}' --batch --level 1 --risk 1 --output-dir {out_dir}/sqlmap --timeout {args.timeout} --forms"
            _, out = run_cmd(cmd, timeout=180)
            if "injectable" in out.lower() or "vulnerable" in out.lower():
                findings.append({"type": "sqli", "severity": "critical", "url": url, "raw": out})
        log(f"{sql_tool} → escaneo completado", "success")

    # ── Checks propios ─────────────────────────────────────────
    # Headers
    log("Revisando headers de seguridad...", "info")
    header_issues = []
    ua = get_random_ua()
    for url in clean_urls[:15]:
        wait_if_needed()
        _, resp = run_cmd(f"curl -sI -A '{ua}' --max-time {args.timeout} '{url}'", timeout=args.timeout+5)
        missing = [h for h in SECURITY_HEADERS if h not in resp.lower()]
        if missing:
            header_issues.append({"url": url, "missing": missing})
    
    # Archivos expuestos
    log("Buscando archivos sensibles...", "info")
    exposed = []
    base_urls = dedupe([re.match(r"(https?://[^/]+)", u).group(1) for u in clean_urls if re.match(r"https?://[^/]+", u)])
    for base in base_urls[:5]:
        for path in EXPOSED_PATHS:
            wait_if_needed()
            _, resp = run_cmd(f"curl -so /dev/null -A '{ua}' -w '%{{http_code}}' --max-time 5 '{base}{path}'", timeout=7)
            if resp and resp.strip() in ["200", "403"]: # 403 a veces indica que el archivo existe pero está protegido
                exposed.append(f"{resp.strip()} → {base}{path}")
                findings.append({"type": "exposed_file", "severity": "medium", "url": f"{base}{path}"})

    # ── Detección de IDOR ──────────────────────────────────────
    log("Buscando candidatos a IDOR...", "info")
    idor_candidates = detect_idor_candidates(clean_urls)
    
    # Verificación automática de los primeros 5
    verified_idor = []
    for candidate in idor_candidates[:5]:
        if candidate.get("poc_url"):
            log(f"  Verificando {candidate['param']}...", "info")
            verified = verify_idor(candidate["poc_url"], candidate["url"])
            candidate["verification"] = verified
            if verified.get("exploitable"):
                verified_idor.append(candidate)
                findings.append({
                    "type": "idor",
                    "severity": "critical",
                    "name": "IDOR - Insecure Direct Object Reference",
                    "url": candidate["url"],
                    "poc": candidate.get("poc"),
                    "verification": verified,
                })
                log(f"  🔥 IDOR detectado: {candidate['url'][:50]}", "warn")
    
    log(f"IDOR → {len(verified_idor)} candidatos verificados", "success")
    
    results = {
        "findings":        findings,
        "header_issues":  header_issues,
        "exposed_files":   exposed,
        "idor_candidates": idor_candidates,
        "verified_idor":  verified_idor,
        "out_dir":        str(out_dir),
    }

    # Persistencia JSON
    save_json(out_dir / "results.json", results)

    log(f"Total hallazgos: {len(findings)}", "success")
    return results

