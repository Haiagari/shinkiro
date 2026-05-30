"""
Advanced Target Validator - OzyRecon v9.0.1
Prevents SSRF, DNS Rebinding and internal infrastructure scanning.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Tuple

PRIVATE_IPV4_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]
PRIVATE_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}


def is_local_host(host: str) -> bool:
    """Return True when a host is obviously local or reserved."""
    if not isinstance(host, str):
        return False

    normalized = host.strip().lower()
    if not normalized:
        return False

    if normalized in LOCAL_HOSTS or normalized.endswith(".local"):
        return True

    try:
        return _is_restricted_ip(ipaddress.ip_address(normalized))
    except ValueError:
        return False


def _is_restricted_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip_obj, ipaddress.IPv4Address):
        return any(ip_obj in network for network in PRIVATE_IPV4_NETWORKS)

    mapped = ip_obj.ipv4_mapped
    if mapped is not None:
        return _is_restricted_ip(mapped)

    return any(ip_obj in network for network in PRIVATE_IPV6_NETWORKS)


def _resolve_ip_addresses(target: str) -> set[str]:
    infos = socket.getaddrinfo(target, None)
    return {str(info[4][0]) for info in infos if info[4] and info[4][0]}


def is_safe_target(target: str) -> Tuple[bool, str]:
    """
    Strictly validates a target domain or IP.
    Returns (is_safe, reason).
    """
    if not isinstance(target, str):
        return False, "Invalid target type"

    normalized = target.strip().lower()
    if not normalized:
        return False, "Empty target"

    if re.search(r"[;&|`$<>^{}\[\]\s]", normalized):
        return False, "Malicious characters detected"

    try:
        ip_obj = ipaddress.ip_address(normalized)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if _is_restricted_ip(ip_obj):
            return False, f"Target IP {normalized} is restricted"
        return True, "Safe IP"

    try:
        for ip in _resolve_ip_addresses(normalized):
            if _is_restricted_ip(ipaddress.ip_address(ip)):
                return False, f"Domain {normalized} resolves to restricted IP"
    except socket.gaierror:
        if is_local_host(normalized):
            return False, "Restricted keyword detected"
        return True, "Domain not resolvable"

    return True, "Safe target"


__all__ = ["is_local_host", "is_safe_target"]
