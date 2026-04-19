"""
Scanners Wrappers Module
Wrappers unificados para herramientas de scanning externas.
"""

from .naabu import NaabuWrapper, naabu, PortResult
from .nmap import NmapWrapper, nmap, ServiceInfo
from .http_clients import OzyHTTPClient, ReconHTTPClient, http_client, recon_http_client, create_client

__all__ = [
    # Naabu
    'NaabuWrapper',
    'naabu',
    'PortResult',
    # Nmap
    'NmapWrapper',
    'nmap',
    'ServiceInfo',
    # HTTP Clients
    'OzyHTTPClient',
    'ReconHTTPClient',
    'http_client',
    'recon_http_client',
    'create_client',
]