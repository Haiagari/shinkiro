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


class NaabuWrapper:
    """Wrapper para Naabu."""
    
    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._find_binary()
        self.config = config
    
    def _find_binary(self) -> str:
        """Busca el binario de Naabu."""
        possible_paths = [
            Path("tools/go/bin/naabu"),
            Path.home() / "go" / "bin" / "naabu",
            Path("/usr/local/bin/naabu"),
            Path("/usr/bin/naabu"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Intentar usar PATH
        try:
            result = subprocess.run(["which", "naabu"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        raise ToolNotFoundError("Naabu not found. Install with: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    
    def scan(self, host: str, ports: Optional[str] = None, rate: int = 100) -> List[PortResult]:
        """
        Escanea puertos en un host.
        
        Args:
            host: Host objetivo
            ports: Puertos a escanear (ej: "80,443,8080" o "top-100")
            rate: Rate de requests por segundo
        
        Returns:
            Lista de PortResult
        """
        cmd = [self.binary_path, "-host", host, "-json"]
        
        if ports:
            cmd.extend(["-ports", ports])
        
        cmd.extend(["-rate", str(rate)])
        
        # Agregar rate limiting desde config
        if self.config.auto_rate_limit_enabled:
            cmd.extend([""-c", str(self.config.max_requests_per_min)])
        
        logger.info(f"Running naabu: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode not in [0, 1]:  # 0 = success, 1 = no results
                raise ToolExecutionError(f"Naabu error: {result.stderr}")
            
            return self._parse_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Naabu timeout")
        except Exception as e:
            raise ToolExecutionError(f"Naabu execution failed: {e}")
    
    def _parse_output(self, output: str) -> List[PortResult]:
        """Parsea el output JSON de Naabu."""
        results = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
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
            except json.JSONDecodeError:
                continue
        
        return results
    
    def scan_top_ports(self, host: str, top: int = 100) -> List[PortResult]:
        """Escanea los top puertos más comunes."""
        return self.scan(host, ports=f"top-{top}")
    
    def scan_critical(self, host: str) -> List[PortResult]:
        """Escanea puertos críticos comunes."""
        critical_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
        return self.scan(host, ports=critical_ports)


# Instancia global
naabu = NaabuWrapper()