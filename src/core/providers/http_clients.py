"""
OzyRecon v6.0 — Stealth HTTP Client
Implementa TLS Fingerprinting y Camaleón Stealth.
Resilience Mode: Fallback a requests si curl_cffi no está disponible.
"""

import time
import random
from typing import Dict, Optional, Any
from src.core.logging import get_logger
from src.opsec.chameleon import chameleon

# Intento de importar curl_cffi con fallback a requests
try:
    from curl_cffi import requests as stealth_requests
    HAS_STEALTH = True
except ImportError:
    import requests as stealth_requests
    HAS_STEALTH = False

logger = get_logger('http-client')

class OzyHTTPClient:
    """
    v6.0 — HTTP Client con Evasión y Fallback.
    """
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.identity = chameleon.generate_identity()
        self.last_request_time = 0
        self.min_interval = 1.0 if HAS_STEALTH else 0.1 # Jitter agresivo solo si hay sigilo
        
        if not HAS_STEALTH:
            logger.warning("Stealth Layer (curl_cffi) not found. Running in Legacy Mode.")

    def _wait_for_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed + random.uniform(0.05, 0.2))
        self.last_request_time = time.time()

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        impersonate: Optional[str] = None,
        **kwargs
    ) -> Any:
        self._wait_for_rate_limit()
        
        request_headers = self.identity.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Gestionar timeout
        req_timeout = kwargs.pop('timeout', self.timeout)
        
        try:
            if HAS_STEALTH:
                imp = impersonate or self.identity.tls_profile
                if imp == 'chrome': imp = 'chrome124'
                
                return stealth_requests.request(
                    method, url, 
                    headers=request_headers, 
                    impersonate=imp,
                    timeout=req_timeout,
                    **kwargs
                )
            else:
                # Modo Legacy sin impersonation
                return stealth_requests.request(
                    method, url, 
                    headers=request_headers, 
                    timeout=req_timeout,
                    **kwargs
                )
            
        except Exception as e:
            logger.error(f"Request failed: {url} - {e}")
            raise

    def get(self, url: str, **kwargs): return self.request("GET", url, **kwargs)
    def post(self, url: str, **kwargs): return self.request("POST", url, **kwargs)

# Instancias
http_client = OzyHTTPClient()
recon_http_client = OzyHTTPClient()

def create_client(**kwargs) -> OzyHTTPClient:
    return OzyHTTPClient(**kwargs)
