"""
JS LinkFinder — Native Python Implementation
Extrae endpoints y rutas ocultas de archivos JavaScript usando Regex.
Basado en la lógica de LinkFinder de @GerbenJavado.
"""

import re
import requests
from pathlib import Path
from .utils import log, get_stealth_headers

# Regex oficial de LinkFinder para encontrar endpoints
JS_URL_REGEX = r"""
  (?:"|')                               # Start quote
  (
    ((?:[a-zA-Z]{1,10}://|//)           # Scheme or //
    [^"'/]{1,}\. [a-zA-Z]{2,}[^"']{0,}) # Domain
    |
    ((?:/|\.\./|\./)                    # Relative path
    [^"'><,;| *()(%%^/][^"'><,;| *()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/               # Just a path
    [a-zA-Z0-9_\-/]{1,}\.[a-z]{1,4})
    |
    ([a-zA-Z0-9_\-]{1,}\.php)           # PHP files
    |
    ([a-zA-Z0-9_\-]{1,}\.asp)           # ASP files
  )
  (?:"|')                               # End quote
"""

def extract_endpoints_from_js(js_url: str) -> list:
    """Descarga un JS y extrae todos los posibles endpoints."""
    endpoints = []
    headers = get_stealth_headers()
    
    try:
        r = requests.get(js_url, headers=headers, timeout=15, verify=False)
        if r.status_code == 200:
            content = r.text
            matches = re.finditer(JS_URL_REGEX, content, re.VERBOSE)
            for match in matches:
                endpoints.append(match.group(1))
    except Exception as e:
        log(f"Error analizando JS {js_url}: {e}", "debug")
        
    return list(set(endpoints))

def run_js_discovery(js_urls: list, out_dir: Path) -> dict:
    """Orquesta el análisis de múltiples archivos JS."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"Iniciando LinkFinder nativo sobre {len(js_urls)} archivos JS...", "info")
    
    all_found = []
    for url in js_urls:
        found = extract_endpoints_from_js(url)
        all_found.extend(found)
    
    all_found = list(set(all_found))
    output_file = out_dir / "js_endpoints.txt"
    with open(output_file, "w") as f:
        for link in all_found:
            f.write(link + "\n")
            
    log(f"LinkFinder completado. {len(all_found)} endpoints extraídos.", "success")
    return {"endpoints": all_found, "count": len(all_found), "file": str(output_file)}
