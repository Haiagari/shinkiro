"""
HTTP Clients para OzyRecon
Wrapper unificado para requests HTTP con soporte OPSEC.
"""

import random
import time
from typing import Dict, Optional, Callable
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.config import config
from src.core.logging import get_logger
from src.opsec.identity_rotation import identity_rotation, recon_identity_rotation

logger = get_logger('http')


class OzyHTTPClient:
    """
    HTTP Client con OPSEC incorporado.
    Maneja rate limiting, rotación de User-Agents, retries automáticos.
    """
    
    def __init__(
        self,
        user_agent: Optional[str] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        timeout: int = 10
    ):
        self.timeout = timeout
        self.user_agent = user_agent or identity_rotation.get_random_ua()
        self.session = self._create_session(max_retries, backoff_factor)
        self.request_count = 0
        self.last_request_time = 0
        
        # Rate limiting desde config
        self.rate_limit = config.max_requests_per_min
        self.min_interval = 60.0 / self.rate_limit if self.rate_limit > 0 else 0
    
    def _create_session(self, max_retries: int, backoff_factor: float) -> requests.Session:
        """Crea una sesión con retry strategy."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _wait_for_rate_limit(self):
        """Espera si se excedió el rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()
    
    def get_headers(self) -> Dict[str, str]:
        """Genera headers con rotación de User-Agent."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> requests.Response:
        """
        Realiza una request con OPSEC.
        """
        self._wait_for_rate_limit()
        
        # Merge headers
        request_headers = self.get_headers()
        if headers:
            request_headers.update(headers)
        
        # Asegurar timeout
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        
        try:
            response = self.session.request(method, url, headers=request_headers, **kwargs)
            self.request_count += 1
            
            logger.debug(f"{method} {url} -> {response.status_code}")
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {url} - {e}")
            raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request."""
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request."""
        return self.request("POST", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HEAD request."""
        return self.request("HEAD", url, **kwargs)
    
    def rotate_user_agent(self):
        """Rotea el User-Agent para la siguiente request."""
        self.user_agent = identity_rotation.get_random_ua()


class ReconHTTPClient(OzyHTTPClient):
    """HTTP Client optimizado para recon (más discreto)."""
    
    def __init__(self, **kwargs):
        kwargs['user_agent'] = recon_identity_rotation.get_random_ua()
        super().__init__(**kwargs)


# Instancias globales
http_client = OzyHTTPClient()
recon_http_client = ReconHTTPClient()


def create_client(for_recon: bool = False, **kwargs) -> OzyHTTPClient:
    """Factory de HTTP clients."""
    if for_recon:
        return ReconHTTPClient(**kwargs)
    return OzyHTTPClient(**kwargs)