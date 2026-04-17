"""
Detector de WAFs y sistemas de protección.
Ajuste estrategias según el WAF detectado.
"""

import requests
import re
from .utils import log

# Headers que indican WAF
WAF_HEADERS = {
    "server": r".*",
    "x-cdn": r".*",
    "x-served-by": r".*",
    "cf-ray": r".*",
    "x-cloudflare": r".*",
    "x-sucuri": r".*",
    "x-proxycache": r".*",
}

# Patrones en response que indican WAF
WAF_SIGNATURES = [
    # Cloudflare
    (r"cloudflare", "Cloudflare"),
    (r"cf-ray", "Cloudflare"),
    (r"__cfduid", "Cloudflare"),
    (r"checking your browser before accessing", "Cloudflare"),
    
    # AWS WAF
    (r"aws-waf", "AWS WAF"),
    (r"request blocked", "AWS WAF"),
    (r"managed by AWS WAF", "AWS WAF"),
    
    # Akamai
    (r"akamai", "Akamai"),
    (r"akamai ghost", "Akamai"),
    
    # Sucuri
    (r"sucuri", "Sucuri WAF"),
    (r"website firewall", "Sucuri"),
    
    # Wordfence
    (r"wordfence", "Wordfence"),
    (r"blocked by wordfence", "Wordfence"),
    
    # ModSecurity
    (r"mod_security", "ModSecurity"),
    (r"modsecurity", "ModSecurity"),
    (r"not rejected", "ModSecurity"),
    
    # Imunify360
    (r"imunify360", "Imunify360"),
    (r"powered by imunify", "Imunify360"),
    
    # F5 ASM
    (r"big-ip", "F5 ASM"),
    (r"asm request", "F5"),
    
    # Incapsula
    (r"incapsula", "Incapsula"),
    (r"incid", "Incapsula"),
    
    # StackPath
    (r"stackpath", "StackPath"),
    
    # Fastly
    (r"fastly", "Fastly"),
    
    # Azure WAF
    (r"azure waf", "Azure WAF"),
    (r"application gateway", "Azure WAF"),
    
    # DDoS-Guard
    (r"ddos-guard", "DDoS-Guard"),
    
    # ReCaptcha responses
    (r"recaptcha", "reCAPTCHA"),
    (r"google.com/recaptcha", "reCAPTCHA"),
]

# Estrategias por WAF
WAF_STRATEGIES = {
    "cloudflare": {
        "slow": True,
        "delay": 3,
        "avoid_browser_check": True,
        "use_proxies": True,
    },
    "aws_waf": {
        "slow": True,
        "rotate_ips": True,
        "add_standard_headers": True,
    },
    "sucuri": {
        "slow": False,
        "avoid_common_paths": True,
    },
    "wordfence": {
        "slow": False,
        "user_agent": "Mozilla/5.0",
    },
    "default": {
        "slow": False,
        "delay": 1,
    },
}

def detect_waf(url: str) -> dict:
    """
    Detecta si un sitio tiene WAF.
    Retorna: tipo, nombre, nivel de protección.
    """
    log(f"Detectando WAF en: {url}", "info")
    
    waf_type = None
    waf_name = None
    protection_level = "none"
    detected_by = None
    
    try:
        r = requests.get(url, timeout=10, verify=False)
        headers = r.headers
        text = r.text.lower()
        
        # Check headers
        for header_name, pattern in WAF_HEADERS.items():
            value = headers.get(header_name, "")
            if value:
                detected_by = f"header: {header_name}"
                for sig, name in WAF_SIGNATURES:
                    if sig.lower() in value.lower():
                        waf_name = name
                        waf_type = name.lower().replace(" ", "_")
                        break
        
        # Check body
        if not waf_name:
            for sig, name in WAF_SIGNATURES:
                if re.search(sig, text, re.IGNORECASE):
                    waf_name = name
                    waf_type = name.lower().replace(" ", "_")
                    detected_by = "body signature"
                    break
        
        # Check específico de respuesta 403
        if r.status_code == 403:
            if "cloudflare" in text or "cf-ray" in headers:
                waf_name = "Cloudflare"
                waf_type = "cloudflare"
                protection_level = "high"
            elif "access denied" in text or "blocked" in text:
                protection_level = "medium"
        
        # Determinar nivel
        if waf_name:
            if waf_name in ["Cloudflare", "AWS WAF", "Imunify360"]:
                protection_level = "high"
            elif waf_name in ["Sucuri", "Wordfence", "ModSecurity"]:
                protection_level = "medium"
            else:
                protection_level = "low"
        
    except Exception as e:
        log(f"Error detectando WAF: {e}", "error")
    
    result = {
        "detected": bool(waf_name),
        "name": waf_name,
        "type": waf_type,
        "protection": protection_level,
        "strategy": WAF_STRATEGIES.get(waf_type, WAF_STRATEGIES["default"]),
    }
    
    if waf_name:
        log(f"  ✓ WAF detectado: {waf_name} ({protection_level})", "warn")
    else:
        log(f"  ✓ Sin WAF detectado", "success")
    
    return result

def get_safe_headers(user_agent: str = None) -> dict:
    """
    Headers que parecen más legítimo para evitar blocks.
    """
    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

def adjust_strategy(waf: dict) -> dict:
    """
    Ajusta parámetros según el WAF detectado.
    """
    strategy = waf.get("strategy", {})
    
    adjusted = {
        "delay": strategy.get("delay", 0),
        "threads": 10 if strategy.get("slow") else 50,
        "timeout": 30 if strategy.get("slow") else 10,
        "add_proxy": strategy.get("use_proxies", False),
    }
    
    return adjusted

def run_waf_detection(urls: list, out_dir=None) -> dict:
    """
    Detecta WAFs en una lista de URLs.
    """
    results = {}
    
    # Usar solo el dominio base
    base_urls = set()
    for url in urls[:10]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_urls.add(f"{parsed.scheme}://{parsed.netloc}")
    
    for base in base_urls:
        waf = detect_waf(base)
        if waf["detected"]:
            results[base] = waf
    
    return results