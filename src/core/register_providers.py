"""
Provider Registration
Registra todos los providers con tool_manager.
Se debe importar después de que todos los módulos estén cargados.
"""

from src.core.tool_manager import tool_manager
from src.core.providers import (
    SubfinderProvider,
    NaabuProvider,
    NmapProvider,
    NucleiProvider,
    GenericDiscoveryProvider,
    FuzzingProvider,
    DBProbeProvider,
)

# Asset Discovery
tool_manager.register_provider("asset_discovery", SubfinderProvider())
tool_manager.register_provider("asset_discovery", GenericDiscoveryProvider(
    "assetfinder", "assetfinder", "{bin} --subs-only {target} > {out}"
))
tool_manager.register_provider("asset_discovery", GenericDiscoveryProvider(
    "amass", "amass", "{bin} enum -passive -timeout 2 -d {target} -o {out}"
))

# Port & Service Discovery
naabu = NaabuProvider()
tool_manager.register_provider("port_scan", naabu)
tool_manager.register_provider("service_discovery", naabu)

nmap = NmapProvider()
tool_manager.register_provider("service_discovery", nmap)

# DNS & Live Detection
tool_manager.register_provider("dns_resolution", GenericDiscoveryProvider(
    "dnsx", "dnsx", "{bin} -l {target} -silent -o {out} -t {threads}"
))
tool_manager.register_provider("live_detection", GenericDiscoveryProvider(
    "httpx", "httpx", "{bin} -l {target} -silent -status-code -title -tech-detect -o {out} -threads {threads}"
))

# Template Scanning
tool_manager.register_provider("template_scan", NucleiProvider())

# Vulnerability Scanning
tool_manager.register_provider("web_fuzzing", FuzzingProvider("dalfox", "dalfox"))
tool_manager.register_provider("db_probe", DBProbeProvider("ghauri", "ghauri"))
tool_manager.register_provider("db_probe", DBProbeProvider("sqlmap", "sqlmap"))
