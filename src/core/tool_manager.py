"""
PromptWall Tool Manager & Capabilities system
Abstrae la ejecución de herramientas en capacidades lógicas.
"""

import time
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
            cls._instance._hooks = {
                "provider_registered": [],
                "before_capability": [],
                "after_capability": [],
                "provider_failed": [],
                "manifest_loaded": [],
            }
            cls._instance._tool_timings = []
            cls._instance._initialized = False
        return cls._instance

    def register_hook(self, event: str, callback):
        """Registra un hook simple para extensibilidad tipo plugin."""
        if event not in self._hooks:
            self._hooks[event] = []
        if callback not in self._hooks[event]:
            self._hooks[event].append(callback)

    def emit_hook(self, event: str, **payload):
        for callback in self._hooks.get(event, []):
            try:
                callback(event, **payload)
            except Exception as e:
                logger.debug("Hook %s failed: %s", event, e)

    def _init_from_manifest(self):
        """Carga herramientas dinámicamente desde el manifiesto YAML."""
        if getattr(self, "_initialized", False):
            return
        logger.info("Initializing ToolManager from manifest...")
        manager = ManifestManager()
        try:
            tools = manager.get_available_tools()
            for tool in tools:
                self._register_tool_entry(tool, manager)
            self.emit_hook("manifest_loaded", tool_count=len(tools))
        except Exception as e:
            logger.error(f"Failed to load manifest: {e}")
        finally:
            self._initialized = True

    def _ensure_initialized(self):
        if not getattr(self, "_initialized", False):
            self._init_from_manifest()

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
        self.emit_hook("provider_registered", capability=capability, provider=provider.name)

    def register_plugin(self, capability: str, provider: BaseProvider):
        """Alias explícito para registrar plugins/herramientas dinámicas."""
        self.register_provider(capability, provider)

    def reset_timings(self):
        """Clear collected tool timings for a fresh flow."""
        self._tool_timings = []

    def get_timing_summary(self) -> Dict[str, Any]:
        """Return a compact timing summary sorted by slowest tool first."""
        ordered = sorted(self._tool_timings, key=lambda item: item["elapsed"], reverse=True)
        return {
            "count": len(ordered),
            "total_elapsed": round(sum(item["elapsed"] for item in ordered), 3),
            "slowest_tools": ordered[:5],
        }

    def run_capability(self, capability: str, target: Any, all_providers: bool = False, **kwargs) -> Any:
        """
        Ejecuta proveedores para una capacidad con inteligencia OPSEC.
        """
        self._ensure_initialized()
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
            self.emit_hook("before_capability", capability=capability, provider=provider.name, target=target)
            started_at = time.perf_counter()
            try:
                # Aplicar Jitter/Delay si es necesario
                if opsec:
                    opsec.apply_jitter()

                res = provider.execute(target, capability=capability, **kwargs)
                elapsed = round(time.perf_counter() - started_at, 3)
                self._tool_timings.append({
                    "capability": capability,
                    "provider": provider.name,
                    "target": target,
                    "elapsed": elapsed,
                    "status": "success",
                })
                
                if not all_providers and res:
                    self.emit_hook("after_capability", capability=capability, provider=provider.name, target=target, result=res)
                    return res
                
                if isinstance(res, list):
                    results.extend(res)
                elif res:
                    results.append(res)
                self.emit_hook("after_capability", capability=capability, provider=provider.name, target=target, result=res)
            except Exception as e:
                elapsed = round(time.perf_counter() - started_at, 3)
                self._tool_timings.append({
                    "capability": capability,
                    "provider": provider.name,
                    "target": target,
                    "elapsed": elapsed,
                    "status": "failed",
                })
                logger.error(f"Provider {provider.name} failed: {e}")
                self.emit_hook("provider_failed", capability=capability, provider=provider.name, target=target, error=str(e))
                # Record error in context if available
                from src.core.context import get_context
                ctx = get_context()
                if ctx:
                    ctx.record_event("capability", "provider failed", provider=provider.name, error=str(e))
                continue
        
        # Deduplicar si es una lista de strings (común en discovery)
        if all_providers and results and isinstance(results[0], str):
            results = list(set(results))
            
        return results if all_providers else (results[0] if results else None)

# Instancia global
tool_manager = ToolManager()
