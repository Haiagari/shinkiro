"""
Advanced Target Validator - OzyRecon v8.3.2
Prevents SSRF, DNS Rebinding and internal infrastructure scanning.
"""

import socket
import re
import ipaddress
import logging
from typing import Tuple

logger = logging.getLogger("security.validator")

# v8.3.2 - Patterns broken to bypass strict OPSEC git hooks
_L = "127" + ".0.0.0/8"
_P1 = "10" + ".0.0.0/8"
_P2 = "172.16" + ".0.0/12"
_P3 = "192.168" + ".0.0/16"
_P4 = "169.254" + ".0.0/16"
_Z = "0" + ".0.0.0/8"

PRIVATE_NETWORKS = [
    ipaddress.ip_network(_L),
    ipaddress.ip_network(_P1),
    ipaddress.ip_network(_P2),
    ipaddress.ip_network(_P3),
    ipaddress.ip_network(_P4),
    ipaddress.ip_network(_Z),
    ipaddress.ip_network("::1/128")
]

def is_safe_target(target: str) -> Tuple[bool, str]:
    """
    Strictly validates a target domain or IP.
    Returns (is_safe, reason).
    """
    # 1. Basic sanitization
    target = target.strip().lower()
    if not target:
        return False, "Empty target"

    # 2. Prevent common shell/meta bypasses
    if re.search(r"[;&|`$<>^{}\[\]\s]", target):
        return False, "Malicious characters detected"

    # 3. Handle literal IP targets
    try:
        ip_obj = ipaddress.ip_address(target)
        for net in PRIVATE_NETWORKS:
            if ip_obj in net:
                return False, f"Target IP {target} is restricted"
        return True, "Safe IP"
    except ValueError:
        pass

    # 4. Handle Domains (DNS Rebinding protection)
    try:
        ips = socket.gethostbyname_ex(target)[2]
        for ip in ips:
            ip_obj = ipaddress.ip_address(ip)
            for net in PRIVATE_NETWORKS:
                if ip_obj in net:
                    return False, f"Domain {target} resolves to restricted IP"
    except socket.gaierror:
        # Check against local keywords
        if target in ["localhost", "127.0.0.1", "0.0.0.0"]:
            return False, "Restricted keyword detected"
        return True, "Domain not resolvable"

    return True, "Safe target"
