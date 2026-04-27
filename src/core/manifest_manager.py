from typing import List, Optional, Type
from pydantic import BaseModel, Field
import yaml
import os
import shutil
import importlib
import logging

logger = logging.getLogger(__name__)

class ToolEntry(BaseModel):
    name: str
    executable: str
    adapter: str
    categories: List[str]
    description: Optional[str] = None
    cmd_template: Optional[str] = None
    enabled: bool = True

class ToolManifest(BaseModel):
    tools: List[ToolEntry]

class ManifestManager:
    def load(self, path: str = "resources/manifest.yaml") -> ToolManifest:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Manifest not found: {path}")
            
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            
        return ToolManifest(**data)

    def validate_binaries(self, manifest: ToolManifest) -> None:
        """Verifica si los binarios existen en el PATH. Deshabilita si no."""
        for tool in manifest.tools:
            if tool.enabled:
                if not shutil.which(tool.executable):
                    logger.warning(f"Binario '{tool.executable}' no encontrado en PATH. Deshabilitando '{tool.name}'.")
                    tool.enabled = False

    def get_available_tools(self, path: str = "resources/manifest.yaml") -> List[ToolEntry]:
        """Orquestación completa: carga, valida y filtra herramientas habilitadas."""
        manifest = self.load(path)
        self.validate_binaries(manifest)
        return [t for t in manifest.tools if t.enabled]

    def get_provider_class(self, adapter_name: str) -> Type:
        """Carga dinámicamente la clase del adaptador desde src.core.providers."""
        try:
            module = importlib.import_module("src.core.providers")
            return getattr(module, adapter_name)
        except (ImportError, AttributeError) as e:
            logger.error(f"Error cargando el adaptador '{adapter_name}': {e}")
            raise
