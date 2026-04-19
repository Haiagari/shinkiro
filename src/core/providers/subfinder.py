"""
Subfinder Provider para Asset Discovery
"""

import subprocess
from pathlib import Path
from typing import List
from src.core.providers.base import BaseProvider, tool_manager
from src.utils import log

class SubfinderProvider(BaseProvider):
    def __init__(self):
        super().__init__("subfinder", "subfinder")

    def execute(self, target: str, **kwargs) -> List[str]:
        if not self.is_available():
            return []
        
        output_file = Path("runtime/temp") / f"subfinder_{target}.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        threads = kwargs.get("threads", 50)
        
        cmd = [self.path, "-d", target, "-silent", "-all", "-o", str(output_file), "-t", str(threads)]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            if output_file.exists():
                with open(output_file) as f:
                    return [line.strip() for line in f if line.strip()]
        except Exception as e:
            log.error(f"Subfinder execution failed: {e}")
            
        return []

# Register
tool_manager.register_provider("asset_discovery", SubfinderProvider())
