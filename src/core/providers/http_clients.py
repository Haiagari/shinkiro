"""
OzyRecon v6.0 — Stealth HTTP Client
Implementa TLS Fingerprinting y Camaleón Stealth.
Resilience Mode: Fallback a requests si curl_cffi no está disponible.
"""

import time
import random
from typing import Dict, Optional, Any, Union
import certifi
from src.core.logging import get_logger
from src.opsec.chameleon import chameleon
from src.core.errors import StealthSSLError, StealthRequestError

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
        
        if HAS_STEALTH:
            self.session = stealth_requests.Session()
        else:
            self.session = stealth_requests.Session()
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
        verify: Optional[Union[bool, str]] = None,
        **kwargs
    ) -> Any:
        self._wait_for_rate_limit()
        
        request_headers = self.identity.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Gestionar timeout
        req_timeout = kwargs.pop('timeout', self.timeout)
        allow_insecure = kwargs.pop('allow_insecure', False)

        # Configurar verify por defecto con certifi
        if verify is None:
            verify = certifi.where()
        elif verify is False and not allow_insecure:
            raise StealthRequestError("Insecure TLS verification disabled. Set allow_insecure=True to override.")

        try:
            if HAS_STEALTH:
                imp = impersonate or self.identity.tls_profile
                if imp == 'chrome': imp = 'chrome124'
                
                return self.session.request(
                    method, url, 
                    headers=request_headers, 
                    impersonate=imp,
                    verify=verify,
                    timeout=req_timeout,
                    **kwargs
                )
            else:
                # Modo Legacy sin impersonation
                return self.session.request(
                    method, url, 
                    headers=request_headers, 
                    verify=verify,
                    timeout=req_timeout,
                    **kwargs
                )
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Request failed: {url} - {error_msg}")
            
            # Mapeo de excepciones
            if "SSL" in error_msg or "certificate" in error_msg.lower():
                raise StealthSSLError(f"SSL/TLS Error: {error_msg}") from e
            
            raise StealthRequestError(f"Request Error: {error_msg}") from e

    def get(self, url: str, **kwargs): return self.request("GET", url, **kwargs)
    def post(self, url: str, **kwargs): return self.request("POST", url, **kwargs)

# Instancias
http_client = OzyHTTPClient()
recon_http_client = OzyHTTPClient()

def create_client(**kwargs) -> OzyHTTPClient:
    return OzyHTTPClient(**kwargs)
