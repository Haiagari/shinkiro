"""
Wrapper para Nmap (Network Scanner)
Provee fingerprinting y escaneo detallado de servicios.
"""

import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from src.core.config import config
from src.core.logging import get_logger
from src.core.errors import ToolNotFoundError, ToolExecutionError

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


class NmapWrapper:
    """Wrapper para Nmap."""
    
    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or self._find_binary()
    
    def _find_binary(self) -> str:
        """Busca el binario de Nmap."""
        possible_paths = [
            Path("/usr/bin/nmap"),
            Path("/usr/local/bin/nmap"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Intentar usar PATH
        try:
            result = subprocess.run(["which", "nmap"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        raise ToolNotFoundError("Nmap not found. Install with: apt install nmap")
    
    def scan(self, host: str, ports: Optional[str] = None, 
             service_detection: bool = True, os_detection: bool = False,
             scripts: Optional[str] = None) -> List[ServiceInfo]:
        """
        Escanea un host con Nmap.
        
        Args:
            host: Host objetivo
            ports: Puertos a escanear
            service_detection: Habilitar detección de servicios
            os_detection: Habilitar detección de SO
            scripts: Scripts de NSE a ejecutar
        
        Returns:
            Lista de ServiceInfo
        """
        cmd = [self.binary_path, "-oX", "-", host]
        
        if ports:
            cmd.extend(["-p", ports])
        
        if service_detection:
            cmd.append("-sV")
        
        if os_detection:
            cmd.append("-O")
        
        if scripts:
            cmd.extend(["--script", scripts])
        
        # Output format
        cmd.extend(["-T4", "-v"])
        
        logger.info(f"Running nmap: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode not in [0, 1]:
                raise ToolExecutionError(f"Nmap error: {result.stderr}")
            
            return self._parse_xml_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError("Nmap timeout")
        except Exception as e:
            raise ToolExecutionError(f"Nmap execution failed: {e}")
    
    def _parse_xml_output(self, xml_output: str) -> List[ServiceInfo]:
        """Parsea el output XML de Nmap."""
        # Usar expresión simple para extraer datos
        # Para producción, usar xml.etree.ElementTree
        results = []
        
        # Extraer puertos
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
                    port=current_port,
                    protocol=current_protocol or "tcp",
                    service=service_match.group(1),
                    state=current_state,
                    product=service_match.group(2),
                    version=service_match.group(3)
                ))
                current_port = None
        
        return results
    
    def quick_scan(self, host: str) -> List[ServiceInfo]:
        """Escaneo rápido de servicios."""
        return self.scan(host, ports="top-100", service_detection=True)
    
    def full_scan(self, host: str) -> List[ServiceInfo]:
        """Escaneo completo con detección de SO."""
        return self.scan(host, service_detection=True, os_detection=True)
    
    def vuln_scan(self, host: str) -> List[ServiceInfo]:
        """Escaneo con scripts de vulnerabilidades."""
        return self.scan(host, scripts="vuln", service_detection=True)


# Instancia global
nmap = NmapWrapper()