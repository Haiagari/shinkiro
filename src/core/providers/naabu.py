"""
Wrapper para Naabu (Port Scanner)
Provee una interfaz unificada para escaneo de puertos.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from src.core.config import config
from src.core.logging import get_logger
from src.core.errors import ToolNotFoundError, ToolExecutionError
from src.core.providers.base import BaseProvider

logger = get_logger('naabu')


@dataclass
class PortResult:
    """Resultado de un escaneo de puertos."""
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""


class NaabuProvider(BaseProvider):
    """Proveedor Naabu para la capacidad port_scan."""
    
    def __init__(self):
        super().__init__("naabu", "naabu")
        self.config = config

    def execute(self, host: str, **kwargs) -> List[PortResult]:
        return self.scan(host, **kwargs)
    
    def scan(self, host: str, ports: Optional[str] = None, rate: int = 100, **kwargs) -> List[PortResult]:
        """
        Escanea puertos en un host.
        """
        if not self.is_available():
            return []

        cmd = [self.path, "-host", host, "-json"]
        
        if ports:
            cmd.extend(["-ports", ports])
        
        cmd.extend(["-rate", str(rate)])
        
        if self.config.auto_rate_limit_enabled:
            cmd.extend(["-c", str(self.config.max_requests_per_min)])
        
        logger.info(f"Running naabu: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode not in [0, 1]:
                raise ToolExecutionError(f"Naabu error: {result.stderr}")
            
            return self._parse_output(result.stdout)
            
        except Exception as e:
            logger.error(f"Naabu failed: {e}")
            return []
    
    def _parse_output(self, output: str) -> List[PortResult]:
        results = []
        for line in output.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                results.append(PortResult(
                    host=data.get('host', ''),
                    port=data.get('port', 0),
                    protocol=data.get('protocol', 'tcp'),
                    state=data.get('state', 'open'),
                    service=data.get('service', ''),
                    version=data.get('version', '')
                ))
            except Exception: continue
        return results
