"""
Censys Provider para Inteligencia Pasiva
Consulta la infraestructura global vía Censys Search API.
"""

import requests
import base64
from typing import List
from src.core.providers.base import BaseProvider
from src.core.providers.naabu import PortResult
from src.core.logging import get_logger
from src.core.config import config

logger = get_logger('provider.censys')

class CensysProvider(BaseProvider):
    """Proveedor para recolectar datos de activos desde la API de Censys."""
    
    def __init__(self):
        super().__init__("censys", "api")
        self.api_id = config.censys_id
        self.api_secret = config.censys_secret

    def is_available(self) -> bool:
        return bool(self.api_id and self.api_secret)

    def execute(self, target: str, **kwargs) -> List[PortResult]:
        """Busca el target en Censys y devuelve puertos abiertos."""
        if not self.is_available():
            logger.debug("Censys API keys not configured")
            return []

        logger.info(f"Querying Censys for {target}...")
        
        # Censys usa Auth Basic (ID:Secret)
        auth = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode()).decode()
        url = f"https://search.censys.io/api/v2/hosts/search?q={target}"
        headers = {
            "Authorization": f"Basic {auth}",
            "Accept": "application/json"
        }

        try:
            res = requests.get(url, headers=headers, timeout=20)
            if res.status_code != 200:
                logger.error(f"Censys API error: {res.text}")
                return []

            data = res.json()
            results = []
            
            # Navegar por los hits de la API v2 de Censys
            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip")
                services = hit.get("services", [])
                
                for svc in services:
                    port = svc.get("port")
                    if port:
                        results.append(PortResult(
                            host=ip,
                            port=port,
                            service=svc.get("service_name", ""),
                            state="open"
                        ))
            
            logger.info(f"Censys found {len(results)} services for {target}")
            return results

        except Exception as e:
            logger.error(f"Failed to query Censys: {e}")
            return []
