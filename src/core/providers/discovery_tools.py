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
        
        # Preparar el comando base (sin redirección shell)
        template = self.cmd_template
        use_redirection = " > " in template
        if use_redirection:
            template = template.split(" > ")[0]

        # Manejo robusto de placeholders (v8.3.2 Fix)
        # 1. Resolver placeholders simples
        cmd_str = template.replace("{bin}", self.path)
        cmd_str = cmd_str.replace("{target}", target)
        cmd_str = cmd_str.replace("{out}", str(out_file))
        cmd_str = cmd_str.replace("{threads}", str(kwargs.get("threads", 50)))
        
        # 2. Parsear el comando base con shlex
        import shlex
        cmd_args = shlex.split(cmd_str)
        
        # 3. Inyectar stealth_flags como lista (evita problemas de quoting)
        if "{stealth_flags}" in cmd_args:
            idx = cmd_args.index("{stealth_flags}")
            cmd_args[idx:idx+1] = self._get_stealth_flags()
        else:
            # Si no está explícito en el template, los agregamos al final
            cmd_args.extend(self._get_stealth_flags())

        capability = kwargs.get("capability")
        
        logger.info(f"Running {self.name} on {target} (Safe Mode)")
        try:
            if use_redirection:
                with open(out_file, "w") as f_out:
                    self._run_tool(cmd_args, timeout=30, capability=capability, capture=False, check=False, retries=0, stdout=f_out, stderr=subprocess.PIPE)
            else:
                self._run_tool(cmd_args, timeout=30, capability=capability, capture=True, check=False, retries=0)

            if out_file.exists():
                with open(out_file) as f:
                    results = [line.strip() for line in f if line.strip()]
                    logger.debug(f"{self.name} found {len(results)} results")
                    return results
        except Exception as e:
            logger.error(f"Execution of {self.name} failed: {e}")
            
        return []
