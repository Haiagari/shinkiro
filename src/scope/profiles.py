"""
Scan Profiles Module (v9.0.1)
Defines scan profiles with controlled tool sets and limits.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class ScanProfile:
    """
    Scan profile definition with tool constraints.
    """
    name: str
    description: str
    tools: List[str]
    rate_limit: int  # requests per minute
    timeout: int  # seconds
    timeout_policy: Dict[str, int]
    recursive: bool
    requires_authorization: bool


# Profile definitions
PROFILES = {
    "passive": ScanProfile(
        name="passive",
        description="Only public sources, no direct interaction with target",
        tools=[
            "subfinder",
            "assetfinder", 
            "amass_passive",
            "gau",
            "waybackurls",
        ],
        rate_limit=200,
        timeout=30,
        timeout_policy={
            "default": 60,
            "asset_discovery": 60,
            "dns_resolution": 30,
            "live_detection": 30,
            "endpoint_discovery": 45,
            "port_scan": 60,
            "service_discovery": 60,
            "template_scan": 90,
            "web_fuzzing": 120,
            "db_probe": 90,
        },
        recursive=True,
        requires_authorization=False,
    ),
    "safe-active": ScanProfile(
        name="safe-active",
        description="Light validation with low impact",
        tools=[
            "subfinder",
            "assetfinder",
            "amass_passive",
            "dnsx",
            "httpx",
        ],
        rate_limit=100,
        timeout=15,
        timeout_policy={
            "default": 45,
            "asset_discovery": 120,
            "dns_resolution": 30,
            "live_detection": 120,
            "endpoint_discovery": 120,
            "port_scan": 120,
            "service_discovery": 120,
            "template_scan": 120,
            "web_fuzzing": 180,
            "db_probe": 120,
        },
        recursive=False,
        requires_authorization=False,
    ),
    "authorized": ScanProfile(
        name="authorized",
        description="Full authorized scan with all tools",
        tools=[
            "subfinder",
            "assetfinder",
            "amass",
            "dnsx",
            "httpx",
            "nmap",
            "nuclei",
            "katana",
            "gowitness",
        ],
        rate_limit=50,
        timeout=8,
        timeout_policy={
            "default": 120,
            "asset_discovery": 180,
            "dns_resolution": 60,
            "live_detection": 60,
            "endpoint_discovery": 120,
            "port_scan": 300,
            "service_discovery": 600,
            "template_scan": 300,
            "web_fuzzing": 900,
            "db_probe": 180,
        },
        recursive=True,
        requires_authorization=True,
    ),
}


def get_profile(name: str) -> Optional[ScanProfile]:
    """
    Get a scan profile by name.
    
    Args:
        name: Profile name
    
    Returns:
        ScanProfile or None if not found
    """
    return PROFILES.get(name)


def list_profiles() -> Dict[str, Dict[str, Any]]:
    """
    List all available profiles.
    
    Returns:
        Dictionary of profile info
    """
    return {
        name: {
            "description": profile.description,
            "tools": profile.tools,
            "rate_limit": profile.rate_limit,
            "timeout": profile.timeout,
            "timeout_policy": profile.timeout_policy,
            "requires_authorization": profile.requires_authorization,
        }
        for name, profile in PROFILES.items()
    }


def validate_profile(name: str) -> bool:
    """
    Check if a profile exists.
    
    Args:
        name: Profile name
    
    Returns:
        True if profile exists
    """
    return name in PROFILES


__all__ = ["ScanProfile", "PROFILES", "get_profile", "list_profiles", "validate_profile"]
