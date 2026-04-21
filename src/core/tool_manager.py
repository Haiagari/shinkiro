"""
OzyRecon Tool Manager & Capabilities system
Abstrae la ejecución de herramientas en capacidades lógicas.
"""

from typing import List, Dict, Any, Optional
from src.core.logging import get_logger
from src.core.providers.base import BaseProvider

logger = get_logger('tool_manager')

class ToolManager:
    """Gestiona proveedores y resuelve capacidades."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._providers = {}
            cls._instance._capabilities = {
                "asset_discovery": [],
                "service_discovery": [],
                "template_scan": [],
                "web_fuzzing": [],
                "port_scan": [],
                "dns_resolution": [],
                "live_detection": [],
                "db_probe": []
            }
        return cls._instance

    def register_provider(self, capability: str, provider: BaseProvider):
        """Registra un proveedor para una capacidad específica."""
        if capability not in self._capabilities:
            self._capabilities[capability] = []
        # Evitar duplicados (no registrar dos veces el mismo provider)
        for existing in self._capabilities[capability]:
            if existing.name == provider.name:
                logger.debug(f"Provider {provider.name} already registered for {capability}, skipping")
                return
        self._capabilities[capability].append(provider)
        logger.debug(f"Provider {provider.name} registered for {capability}")

    def run_capability(self, capability: str, target: Any, all_providers: bool = False, **kwargs) -> Any:
        """
        Ejecuta proveedores para una capacidad.
        Si all_providers=True, corre todos los disponibles y mezcla resultados (List).
        Si all_providers=False, corre el primero que funcione.
        """
        providers = self._capabilities.get(capability, [])
        if not providers:
            logger.error(f"No providers registered for capability: {capability}")
            return [] if all_providers else None

        results = []
        for provider in providers:
            if provider.is_available():
                logger.info(f"Using provider {provider.name} for {capability}")
                try:
                    res = provider.execute(target, **kwargs)
                    if not all_providers:
                        return res
                    if isinstance(res, list):
                        results.extend(res)
                    else:
                        results.append(res)
                except Exception as e:
                    logger.error(f"Provider {provider.name} failed: {e}")
                    continue
        
        return results if all_providers else None

# Instancia global
tool_manager = ToolManager()
