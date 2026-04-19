"""
Proveedores adicionales para Discovery
"""

import subprocess
from pathlib import Path
from typing import List
from src.core.tool_manager import BaseProvider, tool_manager
from src.utils import run_cmd, read_lines, write_lines

class GenericDiscoveryProvider(BaseProvider):
    def __init__(self, name: str, binary: str, cmd_template: str):
        super().__init__(name, binary)
        self.cmd_template = cmd_template

    def execute(self, target: str, **kwargs) -> List[str]:
        if not self.is_available(): return []
        
        out_file = Path("runtime/temp") / f"{self.name}_{target}.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        cmd = self.cmd_template.format(
            bin=self.path, 
            target=target, 
            out=out_file,
            threads=kwargs.get("threads", 50)
        )
        
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            return read_lines(out_file)
        except:
            return []

# Registrar proveedores
tool_manager.register_provider("asset_discovery", GenericDiscoveryProvider(
    "assetfinder", "assetfinder", "{bin} --subs-only {target} > {out}"
))

tool_manager.register_provider("asset_discovery", GenericDiscoveryProvider(
    "amass", "amass", "{bin} enum -passive -timeout 2 -d {target} -o {out}"
))

tool_manager.register_provider("dns_resolution", GenericDiscoveryProvider(
    "dnsx", "dnsx", "{bin} -l {target} -silent -o {out} -t {threads}"
))

tool_manager.register_provider("live_detection", GenericDiscoveryProvider(
    "httpx", "httpx", "{bin} -l {target} -silent -status-code -title -tech-detect -o {out} -threads {threads}"
))
