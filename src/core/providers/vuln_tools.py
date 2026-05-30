"""
Proveedores para Escaneo de Vulnerabilidades
"""

from pathlib import Path
from typing import List, Dict, Any
from src.core.providers.base import BaseProvider
from src.utils import read_lines
from src.core.runtime_paths import get_temp_dir

class FuzzingProvider(BaseProvider):
    def __init__(self, name: str, binary: str):
        super().__init__(name, binary)

    def execute(self, target_file: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available(): return []
        
        out_file = get_temp_dir() / f"{self.name}_fuzz.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Ejemplo simplificado para dalfox
        cmd = [self.path, "file", target_file, "--silence", "--no-color", "-o", str(out_file)]
        capability = kwargs.get("capability")
        
        try:
            self._run_tool(cmd, timeout=300, capability=capability, capture=True, check=True, retries=1)
            results = []
            for line in read_lines(out_file):
                if "[V]" in line or "[G]" in line:
                    results.append({"type": "xss", "severity": "high", "raw": line})
            return results
        except:
            return []

class DBProbeProvider(BaseProvider):
    def __init__(self, name: str, binary: str):
        super().__init__(name, binary)

    def execute(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available(): return []
        
        # Modo batch seguro
        cmd = [self.path, "-u", url, "--batch", "--level", "1", "--risk", "1"]
        capability = kwargs.get("capability")
        
        try:
            res = self._run_tool(cmd, timeout=180, capability=capability, capture=True, retries=1)
            if "injectable" in res.stdout.lower() or "vulnerable" in res.stdout.lower():
                return [{"type": "sqli", "severity": "critical", "url": url}]
        except:
            pass
        return []
