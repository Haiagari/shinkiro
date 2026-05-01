"""
Proveedores adicionales para Discovery
"""

import subprocess
from pathlib import Path
from typing import List
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir, safe_filename

logger = get_logger('provider.generic')

class GenericDiscoveryProvider(BaseProvider):
    def __init__(self, name: str, binary: str, cmd_template: str):
        super().__init__(name, binary)
        self.cmd_template = cmd_template

    def execute(self, target: str, **kwargs) -> List[str]:
        if not self.is_available():
            logger.error(f"Provider {self.name} binary not found: {self.binary}")
            return []
        
        out_file = get_temp_dir() / f"{self.name}_{safe_filename(target)}.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        cmd = self.cmd_template.format(
            bin=self.path, 
            target=target, 
            out=out_file,
            threads=kwargs.get("threads", 50)
        )
        
        logger.info(f"Running {self.name} on {target}")
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            if out_file.exists():
                with open(out_file) as f:
                    results = [line.strip() for line in f if line.strip()]
                    logger.debug(f"{self.name} found {len(results)} results")
                    return results
        except Exception as e:
            logger.error(f"Execution of {self.name} failed: {e}")
            
        return []
