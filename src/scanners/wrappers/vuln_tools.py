"""
Proveedores para Escaneo de Vulnerabilidades
"""

import subprocess
from pathlib import Path
from typing import List, Dict, Any
from src.core.tool_manager import BaseProvider, tool_manager
from src.utils import read_lines

class FuzzingProvider(BaseProvider):
    def __init__(self, name: str, binary: str):
        super().__init__(name, binary)

    def execute(self, target_file: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available(): return []
        
        out_file = Path("runtime/temp") / f"{self.name}_fuzz.txt"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Ejemplo simplificado para dalfox
        cmd = [self.path, "file", target_file, "--silence", "--no-color", "-o", str(out_file)]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
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
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if "injectable" in res.stdout.lower() or "vulnerable" in res.stdout.lower():
                return [{"type": "sqli", "severity": "critical", "url": url}]
        except:
            pass
        return []

# Registrar
tool_manager.register_provider("web_fuzzing", FuzzingProvider("dalfox", "dalfox"))
tool_manager.register_provider("db_probe", DBProbeProvider("ghauri", "ghauri"))
tool_manager.register_provider("db_probe", DBProbeProvider("sqlmap", "sqlmap"))
