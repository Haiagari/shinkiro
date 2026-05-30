"""
Gowitness Provider para Visual Reconnaissance
Toma screenshots de los targets encontrados.
"""

from pathlib import Path
from typing import List, Any
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_runtime_root

logger = get_logger('provider.gowitness')

class GowitnessProvider(BaseProvider):
    def __init__(self):
        super().__init__("gowitness", "gowitness")
        # Screenshots se guardan en storage/evidence/screenshots/ como pidió el jefe
        self.output_dir = Path("storage/evidence/screenshots")

    def _find_chrome(self) -> str:
        """Busca el binario de Chrome/Chromium en el sistema o localmente."""
        import shutil
        
        # 1. Intentar con binarios del sistema
        for binary in ["google-chrome", "chromium", "google-chrome-stable"]:
            path = shutil.which(binary)
            if path:
                return path
        
        # 2. Intentar con nuestro binario portátil
        local_path = Path("tools/go/bin/chrome")
        if local_path.exists():
            return str(local_path.absolute())
            
        return ""

    def execute(self, target: str, **kwargs) -> str:
        if not self.is_available():
            logger.error("gowitness binary not found. ¡Instalate las herramientas, loco!")
            return ""

        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Si es un archivo, usamos -f, si no single scan
        is_file = Path(target).exists()
        
        cmd = [self.path, "scan"]
        if is_file:
            cmd.extend(["file", "-f", target])
        else:
            cmd.extend(["single", "-u", target])
            
        # Motor de renderizado: Buscar el mejor Chrome disponible
        chrome = self._find_chrome()
        if chrome:
            cmd.extend(["--chrome-path", chrome])
            
        cmd.extend(["--screenshot-path", str(self.output_dir.absolute())])
        
        # Flags de Chameleon para no ser tan ruidosos
        cmd.extend(self._get_stealth_flags())
        capability = kwargs.get("capability")

        logger.info(f"Capturando evidencia visual para {target}")
        try:
            self._run_tool(cmd, timeout=600, capability=capability, capture=True, check=True, retries=1)
            logger.info(f"Screenshots guardadas en {self.output_dir}")
            return str(self.output_dir)
        except Exception as e:
            logger.error(f"Gowitness falló: {e}")
            
        return ""
