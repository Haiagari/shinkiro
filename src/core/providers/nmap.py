"""
Wrapper para Nmap (Network Scanner)
Provee fingerprinting y escaneo detallado de servicios.
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from src.core.config import config
from src.core.logging import get_logger
from src.core.errors import ToolNotFoundError, ToolExecutionError
from src.core.providers.base import BaseProvider

logger = get_logger('nmap')


@dataclass
class ServiceInfo:
    """Información de un servicio detectado."""
    port: int
    protocol: str
    service: str
    state: str
    version: str = ""
    product: str = ""
    extra_info: str = ""


class NmapProvider(BaseProvider):
    """Proveedor Nmap para la capacidad service_discovery."""
    
    def __init__(self):
        super().__init__("nmap", "nmap")

    def execute(self, host: str, **kwargs) -> List[ServiceInfo]:
        return self.scan(host, **kwargs)
    
    def scan(self, host: str, ports: Optional[str] = None, 
             service_detection: bool = True, os_detection: bool = False,
             scripts: Optional[str] = None, **kwargs) -> List[ServiceInfo]:
        """
        Escanea un host con Nmap.
        """
        if not self.is_available():
            return []

        cmd = [self.path, "-oX", "-", host]
        
        if ports: cmd.extend(["-p", ports])
        if service_detection: cmd.append("-sV")
        if os_detection: cmd.append("-O")
        if scripts: cmd.extend(["--script", scripts])
        
        cmd.extend(["-T4", "-v"])
        
        # Inyectar Chameleon Stealth Flags v8.3.2
        cmd.extend(self._get_stealth_flags())
        
        logger.info(f"Running nmap: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode not in [0, 1]:
                raise ToolExecutionError(f"Nmap error: {result.stderr}")
            return self._parse_xml_output(result.stdout)
        except Exception as e:
            logger.error(f"Nmap failed: {e}")
            return []
    
    def _parse_xml_output(self, xml_output: str) -> List[ServiceInfo]:
        results = []
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)">'
        state_pattern = r'<state state="(\w+)"'
        service_pattern = r'<service name="([^"]+)" product="([^"]*)" version="([^"]*)"'
        
        lines = xml_output.split('\n')
        current_port = None
        current_protocol = None
        current_state = "unknown"
        
        for line in lines:
            port_match = re.search(port_pattern, line)
            if port_match:
                current_protocol = port_match.group(1)
                current_port = int(port_match.group(2))
                continue
            state_match = re.search(state_pattern, line)
            if state_match and current_port:
                current_state = state_match.group(1)
                continue
            service_match = re.search(service_pattern, line)
            if service_match and current_port:
                results.append(ServiceInfo(
                    port=current_port, protocol=current_protocol or "tcp",
                    service=service_match.group(1), state=current_state,
                    product=service_match.group(2), version=service_match.group(3)
                ))
                current_port = None
        return results
