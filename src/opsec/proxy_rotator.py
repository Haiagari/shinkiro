"""
OzyRecon Proxy Rotator (v8.3.2)
Manages proxy lists and rotation for stealthy reconnaissance.
"""

import random
import logging
from typing import List, Optional
from src.core.config import config

logger = logging.getLogger("opsec.proxy")

class ProxyRotator:
    """
    Handles proxy rotation and health checking.
    """
    
    def __init__(self):
        self.proxies = config.get("opsec.proxies", [])
        self.enabled = config.get("opsec.proxy_enabled", False)
        if self.enabled and self.proxies:
            logger.info(f"ProxyRotator initialized with {len(self.proxies)} proxies.")
        elif self.enabled:
            logger.warning("Proxy enabled but no proxies found in config.")

    def get_proxy(self) -> Optional[str]:
        """Returns a random proxy from the list."""
        if not self.enabled or not self.proxies:
            return None
        return random.choice(self.proxies)

    def set_ghost_mode(self, enabled: bool):
        """
        Idea 4: Ghost Mode.
        Forces the use of a Tor proxy for full anonymity.
        """
        if enabled:
            self.enabled = True
            tor_proxy = "socks5://127.0.0.1:9050"
            if tor_proxy not in self.proxies:
                self.proxies.insert(0, tor_proxy) # Prioritize Tor
            logger.info("👻 GHOST MODE ACTIVATED: Routing through Tor proxy.")

    def get_tool_flags(self, tool_name: str) -> List[str]:
        """Returns the appropriate proxy flags for a specific tool."""
        proxy = self.get_proxy()
        if not proxy:
            return []

        tool = tool_name.lower()
        
        # Nuclei: -proxy http://...
        if tool == "nuclei":
            return ["-proxy", proxy]
        
        # httpx: -proxy http://...
        if tool == "httpx":
            return ["-proxy", proxy]
        
        # subfinder: -proxy http://...
        if tool == "subfinder":
            return ["-proxy", proxy]
            
        # curl: --proxy http://...
        if tool == "curl":
            return ["--proxy", proxy]

        return []

# Global Instance
proxy_rotator = ProxyRotator()
