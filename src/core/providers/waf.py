"""
WAF Fingerprinting Provider
Identifica firewalls de aplicaciones web usando wafw00f.
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir

logger = get_logger('provider.waf')

class WafProvider(BaseProvider):
    def __init__(self):
        super().__init__("wafw00f", "wafw00f")

    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        if not self.is_available():
            logger.error("wafw00f not found. Sin esto vas a chocar contra un muro.")
            return {}

        # wafw00f no tiene salida JSON nativa muy amigable en versiones viejas, 
        # pero vamos a intentar parsear o usar flags si existen.
        # Por ahora, comando básico y captura.
        
        cmd = [self.path, target]
        
        # Inyectar Chameleon Stealth Flags
        cmd.extend(self._get_stealth_flags())
        capability = kwargs.get("capability")

        logger.info(f"Fingerprinting WAF para {target}")
        try:
            result = self._run_tool(cmd, timeout=60, capability=capability, capture=True, retries=1)
            output = result.stdout
            
            # Heurística simple para el reporte
            waf_found = "is behind" in output
            detected_waf = "None"
            if waf_found:
                # Extraer nombre del WAF (simplificado)
                for line in output.split('\n'):
                    if "is behind" in line:
                        detected_waf = line.split("is behind")[-1].strip()
                        break
            
            return {
                "target": target,
                "waf_detected": waf_found,
                "waf_name": detected_waf,
                "raw_output": output
            }
        except Exception as e:
            logger.debug(f"wafw00f skipped/failed: {e}")
            
        return {}
