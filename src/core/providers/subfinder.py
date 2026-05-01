"""
Subfinder Provider para Asset Discovery
"""

import subprocess
from pathlib import Path
from typing import List
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir, safe_filename

logger = get_logger('provider.subfinder')

class SubfinderProvider(BaseProvider):
    def __init__(self):
        super().__init__("subfinder", "subfinder")

    def execute(self, target: str, **kwargs) -> List[str]:
        if not self.is_available():
            logger.error("Subfinder binary not found")
            return []
        
        output_file = get_temp_dir() / f"subfinder_{safe_filename(target)}.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Mapeo de intención operativa a ejecución técnica
        speed = kwargs.get("speed", "normal")
        threads = kwargs.get("threads", 50)
        
        if speed == "fast": threads = max(threads, 100)
        elif speed == "slow": threads = min(threads, 20)
        
        cmd = [self.path, "-d", target, "-silent", "-all", "-o", str(output_file), "-t", str(threads)]
        
        # Inyectar Chameleon Stealth Flags v7.2
        cmd.extend(self._get_stealth_flags())
        
        # Si la intención es ruido bajo, evitamos el flag "-all"
        if kwargs.get("noise") == "low":
            if "-all" in cmd: cmd.remove("-all")
        
        logger.info(f"Running subfinder on {target}")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            if output_file.exists():
                with open(output_file) as f:
                    results = [line.strip() for line in f if line.strip()]
                    logger.debug(f"Subfinder found {len(results)} subdomains")
                    return results
        except Exception as e:
            logger.error(f"Subfinder execution failed: {e}")
            
        return []
