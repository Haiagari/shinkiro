"""
Shodan Provider para Reconocimiento Pasivo
Obtiene puertos y banners sin tocar el objetivo.
"""

import requests
from typing import List
from src.core.providers.base import BaseProvider
from src.core.providers.naabu import PortResult
from src.core.logging import get_logger
from src.core.config import config

logger = get_logger('provider.shodan')

class ShodanProvider(BaseProvider):
    """Proveedor que consulta la API de Shodan para recolectar inteligencia pasiva."""
    
    def __init__(self):
        super().__init__("shodan", "api")
        self.api_key = config.shodan_api_key

    def is_available(self) -> bool:
        return bool(self.api_key)

    def execute(self, target: str, **kwargs) -> List[PortResult]:
        """Consulta Shodan para obtener puertos abiertos conocidos."""
        if not self.is_available():
            logger.debug("Shodan API key not configured")
            return []

        logger.info(f"Querying Shodan for {target}...")
        url = f"https://api.shodan.io/shodan/host/search?key={self.api_key}&query=hostname:{target}"
        
        try:
            res = requests.get(url, timeout=15)
            if res.status_code != 200:
                logger.error(f"Shodan API error: {res.text}")
                return []

            data = res.json()
            results = []
            
            for match in data.get("matches", []):
                host = match.get("hostnames", [target])[0]
                port = match.get("port")
                if port:
                    results.append(PortResult(
                        host=host,
                        port=port,
                        service=match.get("product", ""),
                        version=match.get("version", ""),
                        state="open"
                    ))
            
            logger.info(f"Shodan found {len(results)} open ports for {target}")
            return results

        except Exception as e:
            logger.error(f"Failed to query Shodan: {e}")
            return []
