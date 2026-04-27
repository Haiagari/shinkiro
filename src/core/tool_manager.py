"""
OzyRecon Tool Manager & Capabilities system
Abstrae la ejecución de herramientas en capacidades lógicas.
"""

from typing import List, Dict, Any, Optional
from src.core.logging import get_logger
from src.core.providers.base import BaseProvider
from src.core.manifest_manager import ManifestManager, ToolEntry

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
            cls._instance._init_from_manifest()
        return cls._instance

    def _init_from_manifest(self):
        """Carga herramientas dinámicamente desde el manifiesto YAML."""
        logger.info("Initializing ToolManager from manifest...")
        manager = ManifestManager()
        try:
            tools = manager.get_available_tools()
            for tool in tools:
                self._register_tool_entry(tool, manager)
        except Exception as e:
            logger.error(f"Failed to load manifest: {e}")

    def _register_tool_entry(self, tool: ToolEntry, manager: ManifestManager):
        """Instancia y registra una herramienta según su entrada en el manifiesto."""
        try:
            adapter_class = manager.get_provider_class(tool.adapter)
            
            # Instanciar el provider
            # Si es GenericDiscoveryProvider o similar, pasar parámetros extra
            if tool.adapter in ["GenericDiscoveryProvider", "FuzzingProvider", "DBProbeProvider"]:
                provider = adapter_class(tool.name, tool.executable, tool.cmd_template)
            else:
                provider = adapter_class()

            for category in tool.categories:
                self.register_provider(category, provider)
                
        except Exception as e:
            logger.error(f"Error registering tool {tool.name}: {e}")

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
        Ejecuta proveedores para una capacidad con inteligencia OPSEC.
        """
        providers = self._capabilities.get(capability, [])
        if not providers:
            logger.error(f"No providers registered for capability: {capability}")
            return [] if all_providers else None

        # --- CAPA OPSEC INTEGRADA ---
        from src.opsec.manager import OPSECManager
        # El manager ya viene en kwargs si el modo lo instanció, si no, creamos uno temporal
        opsec = kwargs.get("opsec_manager")
        
        results = []
        for provider in providers:
            if not provider.is_available():
                continue
                
            # Verificar Kill-Switch antes de cada herramienta
            if opsec and not opsec.should_continue():
                logger.critical(f"OPSEC KILL-SWITCH TRIGGERED. Stopping {capability}")
                break

            logger.info(f"Using provider {provider.name} for {capability}")
            try:
                # Aplicar Jitter/Delay si es necesario
                if opsec:
                    opsec.apply_jitter()

                res = provider.execute(target, **kwargs)
                
                if not all_providers and res:
                    return res
                
                if isinstance(res, list):
                    results.extend(res)
                elif res:
                    results.append(res)
            except Exception as e:
                logger.error(f"Provider {provider.name} failed: {e}")
                continue
        
        # Deduplicar si es una lista de strings (común en discovery)
        if all_providers and results and isinstance(results[0], str):
            results = list(set(results))
            
        return results if all_providers else (results[0] if results else None)

# Instancia global
tool_manager = ToolManager()
