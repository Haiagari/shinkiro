"""
OzyRecon v6.0 — Stealth HTTP Client
Implementa TLS Fingerprinting y Camaleón Stealth usando curl_cffi.
"""

import time
import random
from typing import Dict, Optional, Any
from curl_cffi import requests
from src.core.logging import get_logger
from src.opsec.chameleon import chameleon

logger = get_logger('http-stealth')

class OzyHTTPClient:
    """
    v6.0 — HTTP Client con Evasión de Nivel APT.
    """
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.identity = chameleon.generate_identity()
        self.last_request_time = 0
        self.min_interval = 1.5  # Jitter base
        
    def _wait_for_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed + random.uniform(0.1, 0.5))
        self.last_request_time = time.time()

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        impersonate: Optional[str] = None,
        **kwargs
    ) -> requests.Response:
        """
        Realiza una request con Evasión Avanzada.
        """
        self._wait_for_rate_limit()
        
        # Mezclar headers de la identidad camaleón con los específicos
        request_headers = self.identity.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Determinar perfil de impersonación (v6 feature)
        imp = impersonate or self.identity.tls_profile
        if imp == 'chrome': imp = 'chrome124'
        
        # Gestionar timeout para evitar duplicados en kwargs
        req_timeout = kwargs.pop('timeout', self.timeout)
        
        try:
            # Usamos curl_cffi para evadir TLS Fingerprinting
            response = requests.request(
                method, 
                url, 
                headers=request_headers, 
                impersonate=imp,
                timeout=req_timeout,
                **kwargs
            )
            
            logger.debug(f"[{self.identity.name}] {method} {url} -> {response.status_code}")
            return response
            
        except Exception as e:
            logger.error(f"Stealth Request failed: {url} - {e}")
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def rotate_identity(self):
        """Cambia el disfraz completo."""
        self.identity = chameleon.generate_identity()
        logger.info(f"Identity rotated to: {self.identity.name}")

# Instancia global v6.0
http_client = OzyHTTPClient()
recon_http_client = OzyHTTPClient() # En v6.0 todos son stealth por defecto

def create_client(**kwargs) -> OzyHTTPClient:
    return OzyHTTPClient(**kwargs)
