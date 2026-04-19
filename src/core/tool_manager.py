"""
OzyRecon Tool Manager & Capabilities system
Abstrae la ejecución de herramientas en capacidades lógicas.
"""

import abc
import subprocess
from typing import List, Dict, Any, Optional, Type
from pathlib import Path
from src.core.logging import get_logger
from src.core.errors import ToolNotFoundError, ToolExecutionError

logger = get_logger('tool_manager')

class Capability(abc.ABC):
    """Clase base para una capacidad del sistema."""
    
    @abc.abstractmethod
    def run(self, target: Any, **kwargs) -> Any:
        pass

class BaseProvider(abc.ABC):
    """Clase base para un proveedor de herramientas (herramienta concreta)."""
    
    def __init__(self, name: str, binary: str):
        self.name = name
        self.binary = binary
        self.path = self._find_binary()

    def _find_binary(self) -> str:
        import shutil
        path = shutil.which(self.binary)
        if not path:
            # Check local tools path
            local_path = Path("tools/go/bin") / self.binary
            if local_path.exists():
                return str(local_path.absolute())
        return path if path else ""

    def is_available(self) -> bool:
        return bool(self.path)

    @abc.abstractmethod
    def execute(self, target: Any, **kwargs) -> Any:
        pass

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
                "port_scan": []
            }
        return cls._instance

    def register_provider(self, capability: str, provider: BaseProvider):
        """Registra un proveedor para una capacidad específica."""
        if capability not in self._capabilities:
            self._capabilities[capability] = []
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
