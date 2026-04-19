"""
Nuclei Provider para Template-based Scanning
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any
from src.core.providers.base import BaseProvider, tool_manager
from src.utils import log

class NucleiProvider(BaseProvider):
    def __init__(self):
        super().__init__("nuclei", "nuclei")

    def execute(self, target_list_file: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []
        
        output_file = Path("runtime/temp") / f"nuclei_results.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        severity = kwargs.get("severity", "critical,high,medium")
        rate_limit = kwargs.get("rate_limit", 50)
        
        cmd = [
            self.path, 
            "-l", target_list_file, 
            "-severity", severity, 
            "-o", str(output_file), 
            "-json", "-silent", 
            "-rate-limit", str(rate_limit)
        ]
        
        # Opcionales
        if kwargs.get("update", False):
            subprocess.run([self.path, "-update-templates", "-silent"])

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            results = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        if line.strip():
                            results.append(json.loads(line))
            return results
        except Exception as e:
            log.error(f"Nuclei execution failed: {e}")
            
        return []

# Register
tool_manager.register_provider("template_scan", NucleiProvider())
