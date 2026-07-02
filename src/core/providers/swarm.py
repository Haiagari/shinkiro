"""
Swarm Provider para Delegación de Tareas
Permite que un nodo mande una ejecución a otro nodo remoto.
"""

import requests
from typing import Any
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger

logger = get_logger('provider.swarm')

class SwarmProvider(BaseProvider):
    """
    Proveedor Proxy. No ejecuta binarios locales, 
    manda la tarea a un nodo de PromptWall remoto vía API.
    """
    
    def __init__(self, node_url: str, api_key: str = ""):
        super().__init__("swarm_node", "remote_api")
        self.node_url = node_url.rstrip('/')
        self.api_key = api_key

    def is_available(self) -> bool:
        # Podríamos hacer un health check aquí
        return True

    def execute(self, target: Any, capability: str = "asset_discovery", **kwargs) -> Any:
        """Manda la tarea al nodo remoto."""
        logger.info(f"Delegating {capability} for {target} to remote node: {self.node_url}")
        
        endpoint = f"{self.node_url}/tasks/execute"
        payload = {
            "capability": capability,
            "target": target,
            "options": kwargs
        }
        
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        
        try:
            res = requests.post(endpoint, json=payload, headers=headers, timeout=300)
            if res.status_code == 200:
                return res.json().get("result")
            else:
                logger.error(f"Remote node error ({res.status_code}): {res.text}")
                return None
        except Exception as e:
            logger.error(f"Failed to communicate with remote node: {e}")
            return None
