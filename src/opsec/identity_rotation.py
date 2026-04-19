"""
Rotación de Identidad para OPSEC
Maneja la rotación de User-Agents y identidades.
"""

import random
from typing import List, Optional
from dataclasses import dataclass


# User-Agents comunes (navegadores reales)
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


# User-Agents para herramientas de recon (más discretos)
RECON_USER_AGENTS = [
    "curl/7.88.1",
    "Wget/1.21.3",
    "Python-urllib/3.11",
    "Go-http-client/1.1",
    "python-requests/2.31.0",
]


@dataclass
class Identity:
    """Representa una identidad rotational."""
    user_agent: str
    ip_address: Optional[str] = None
    created_at: int = 0  # timestamp


class IdentityRotation:
    """Maneja la rotación de identidades."""
    
    def __init__(self, use_browsers: bool = True):
        self.use_browsers = use_browsers
        self.ua_list = USER_AGENTS if use_browsers else RECON_USER_AGENTS
        self.rotation_count = 0
        self.current_index = 0
    
    def get_random_ua(self) -> str:
        """Obtiene un User-Agent aleatorio."""
        return random.choice(self.ua_list)
    
    def get_rotating_ua(self) -> str:
        """Obtiene User-Agent rotando secuencialmente."""
        ua = self.ua_list[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.ua_list)
        self.rotation_count += 1
        return ua
    
    def get_ua_for_tool(self, tool: str) -> str:
        """Obtiene User-Agent apropiado para una herramienta específica."""
        if tool in ['subfinder', 'httpx', 'nuclei', 'naabu']:
            return random.choice(RECON_USER_AGENTS)
        return self.get_random_ua()


# Instancia global
identity_rotation = IdentityRotation(use_browsers=True)
recon_identity_rotation = IdentityRotation(use_browsers=False)