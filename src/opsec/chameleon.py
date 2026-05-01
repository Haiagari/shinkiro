"""
OzyRecon v6.0 — Chameleon Stealth Engine
Genera identidades sintéticas completas con consistencia de headers y TLS Fingerprinting.
"""

import random
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass
class ChameleonIdentity:
    name: str
    user_agent: str
    headers: Dict[str, str]
    tls_profile: str  # Compatible con curl_cffi: 'chrome', 'safari', 'firefox'
    platform: str

class ChameleonEngine:
    """
    Motor de identidades sintéticas para evasión de nivel APT.
    """
    
    def __init__(self):
        self.profiles = [
            {
                "name": "Chrome-Win10",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "tls": "chrome",
                "platform": "Windows",
                "ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                "ch_platform": '"Windows"'
            },
            {
                "name": "Firefox-Win10",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
                "tls": "firefox",
                "platform": "Windows",
                "ch_ua": None, # Firefox no usa CH por defecto igual que Chrome
                "ch_platform": None
            },
            {
                "name": "Safari-Mac",
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
                "tls": "safari",
                "platform": "macOS",
                "ch_ua": None,
                "ch_platform": None
            },
            {
                "name": "Chrome-Android",
                "ua": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
                "tls": "chrome",
                "platform": "Android",
                "ch_ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                "ch_platform": '"Android"'
            }
        ]

    def generate_identity(self) -> ChameleonIdentity:
        """Genera una identidad aleatoria consistente."""
        profile = random.choice(self.profiles)
        
        headers = {
            "User-Agent": profile["ua"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "es-ES,es;q=0.9,en;q=0.8", "en-GB,en;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Connection": "keep-alive"
        }
        
        # Inyectar Client-Hints si el perfil lo soporta (Chrome/Chromium)
        if profile["ch_ua"]:
            headers["sec-ch-ua"] = profile["ch_ua"]
            headers["sec-ch-ua-mobile"] = "?1" if "Mobile" in profile["ua"] else "?0"
            headers["sec-ch-ua-platform"] = profile["ch_platform"]

        return ChameleonIdentity(
            name=profile["name"],
            user_agent=profile["ua"],
            headers=headers,
            tls_profile=profile["tls"],
            platform=profile["platform"]
        )

    def get_random_ua(self) -> str:
        """Retorna solo un User-Agent aleatorio para herramientas externas."""
        return random.choice(self.profiles)["ua"]

    def get_stealth_flags(self, tool_name: str) -> List[str]:
        """Genera flags de sigilo para herramientas de CLI (httpx, nuclei, etc)."""
        ua = self.get_random_ua()
        if tool_name.lower() == "httpx":
            # Usamos comillas simples para proteger los espacios en el User-Agent
            return ["-H", f"'User-Agent: {ua}'", "-H", "'Accept-Language: en-US,en;q=0.9'"]
        if tool_name.lower() == "nuclei":
            return ["-H", f"'User-Agent: {ua}'"]
        return []

# Instancia global para v7.2
chameleon = ChameleonEngine()
