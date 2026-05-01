"""
Detector de WAFs y sistemas de protección.
Ajuste estrategias según el WAF detectado.
"""

import re
from src.core.logging import get_logger

logger = get_logger("waf-detector")

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
    (r"cloudflare", "Cloudflare"),
    (r"cf-ray", "Cloudflare"),
    (r"__cfduid", "Cloudflare"),
    (r"aws-waf", "AWS WAF"),
    (r"akamai", "Akamai"),
    (r"sucuri", "Sucuri WAF"),
    (r"mod_security", "ModSecurity"),
    (r"big-ip", "F5 ASM"),
    (r"incapsula", "Incapsula"),
    (r"fastly", "Fastly"),
]

# Estrategias por WAF
WAF_STRATEGIES = {
    "cloudflare": {"slow": True, "delay": 3, "use_proxies": True},
    "aws_waf": {"slow": True, "rotate_ips": True},
    "default": {"slow": False, "delay": 1},
}

def detect_waf(url: str) -> dict:
    """
    Detecta si un sitio tiene WAF.
    Enhanced: Usa headers de sigilo para no ser bloqueado durante la detección.
    """
    logger.info(f"Detectando WAF en: {url}")
    
    waf_type = None
    waf_name = None
    protection_level = "none"
    
    try:
        from src.core.providers.http_clients import http_client
        r = http_client.get(url, timeout=10)
        
        resp_headers = r.headers
        text = r.text.lower()

        
        # Check headers
        for header_name, pattern in WAF_HEADERS.items():
            value = resp_headers.get(header_name, "")
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
            if "cloudflare" in text or "cf-ray" in resp_headers:
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
        logger.error(f"Error detectando WAF: {e}")
    
    result = {
        "detected": bool(waf_name),
        "name": waf_name,
        "type": waf_type,
        "protection": protection_level,
        "strategy": WAF_STRATEGIES.get(waf_type, WAF_STRATEGIES["default"]),
    }
    
    if waf_name:
        logger.warning(f"  WAF detectado: {waf_name} ({protection_level})")
    else:
        logger.info(f"  Sin WAF detectado")
    
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


class WAFDetector:
    """Clase wrapper para detección de WAFs."""
    
    def __init__(self):
        self.headers = WAF_HEADERS
        self.signatures = WAF_SIGNATURES
        self.strategies = WAF_STRATEGIES
    
    def detect(self, url: str) -> dict:
        return detect_waf(url)
    
    def detect_batch(self, urls: list) -> dict:
        return detect_batch(urls)
    
    def get_strategy(self, waf_type: str) -> dict:
        return self.strategies.get(waf_type, self.strategies["default"])


# Instancia global
waf_detector = WAFDetector()
