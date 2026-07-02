"""
PromptWall Stealth HTTP Client (v9.0 - Ghost Edition)
Bypasses WAFs (Cloudflare, Akamai) using JA3/JA4 TLS impersonation.
"""

import random
import logging
from typing import Dict, Any, Optional
from curl_cffi import requests
from src.opsec.chameleon import chameleon
from src.opsec.proxy_rotator import ProxyRotator

logger = logging.getLogger("core.stealth_client")

class StealthClient:
    """
    Advanced HTTP Client that impersonates real browsers at the TLS and Header level.
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.proxy_rotator = ProxyRotator()

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Performs a request with full browser impersonation.
        """
        # 1. Obtener una identidad de Chameleon
        identity = chameleon.generate_identity()
        
        # 2. Configurar el perfil de TLS (JA3 Impersonation)
        impersonate = identity.tls_profile # 'chrome', 'safari', 'firefox'
        
        # 3. Mezclar headers con los de Chameleon
        headers = identity.headers
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
            
        # 4. Configurar Proxy si está disponible (vía ProxyRotator)
        proxy = self.proxy_rotator.get_proxy()
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        
        try:
            logger.debug(f"Stealth Request [{impersonate}]: {method} {url}")
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                impersonate=impersonate,
                timeout=kwargs.pop("timeout", 30),
                verify=kwargs.pop("verify", False),
                **kwargs
            )
            return response
        except Exception as e:
            # Si el error es de resolución de DNS (curl error 6), lo bajamos a DEBUG
            if "Could not resolve host" in str(e):
                logger.debug(f"Host not found (expected in discovery): {url}")
            else:
                logger.error(f"Stealth request failed to {url}: {e}")
            return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

# Global Instance
stealth_client = StealthClient()
