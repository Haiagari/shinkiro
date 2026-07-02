"""
Scope Guard Module (v9.0.1)
Provides strict domain validation to ensure only in-scope assets are processed.
Prevents test data contamination in results.
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

from src.security.target_validator import is_local_host

logger = logging.getLogger("scope.guard")

_MULTI_LEVEL_PUBLIC_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "ltd.uk",
    "plc.uk",
    "me.uk",
    "net.uk",
    "sch.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "com.br",
    "com.mx",
    "com.ar",
    "com.co",
    "com.ec",
    "com.pe",
    "edu.pe",
    "gob.pe",
    "org.pe",
    "co.in",
    "co.id",
    "co.kr",
    "co.jp",
}
_TEST_EXACT_DOMAINS = {
    "evil-corp.com",
    "evil-corp.io",
    "artifact.test",
    "critical-target.test",
}
_TEST_PATTERNS = (".internal", ".corp", ".local")


def _extract_host(value: str) -> str:
    if not value:
        return ""

    candidate = value.strip()
    literal = candidate.strip("[]")
    try:
        ipaddress.ip_address(literal)
        return normalize_host(literal)
    except ValueError:
        pass

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="http")
    host = parsed.hostname or candidate
    return normalize_host(host)


def _extract_host_raw(value: str) -> str:
    if not value:
        return ""

    candidate = value.strip()
    literal = candidate.strip("[]")
    try:
        ipaddress.ip_address(literal)
        return literal.lower().rstrip(".")
    except ValueError:
        pass

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="http")
    host = parsed.hostname or candidate
    return host.lower().strip().rstrip(".")


def in_scope(host: str, root_domain: str) -> bool:
    """
    Strictly validates that a host is within the authorized scope.

    Args:
        host: The host/subdomain to validate
        root_domain: The authorized root domain (e.g., 'example.com')

    Returns:
        True if host is in scope, False otherwise
    """
    if not host or not root_domain:
        return False

    host = normalize_host(host)
    root_domain = normalize_host(root_domain)

    if host == root_domain:
        return True

    return host.endswith("." + root_domain)


def validate_url(url: str, root_domain: str) -> bool:
    """
    Validates that a URL belongs to the authorized scope.

    Args:
        url: Full URL to validate
        root_domain: The authorized root domain

    Returns:
        True if URL is in scope, False otherwise
    """
    try:
        host = _extract_host(url)
        return bool(host) and in_scope(host, root_domain)
    except Exception:
        return False


def normalize_host(host: str) -> str:
    """
    Normalizes a host by removing common prefixes and cleaning.

    Args:
        host: The host to normalize

    Returns:
        Normalized host string
    """
    host = host.lower().strip().rstrip(".")

    prefixes = ["www.", "www2.", "www3.", "ftp.", "mail.", "pop.", "smtp.", "imap."]
    for prefix in prefixes:
        if host.startswith(prefix):
            host = host[len(prefix) :]

    return host


def host_matches_allowed_domain(host: str, allowed_domain: str) -> bool:
    """Return True when a host matches an allowed exact or wildcard domain."""
    normalized_host = _extract_host_raw(host)
    normalized_allowed = allowed_domain.strip().lower().strip(".")
    if not normalized_host or not normalized_allowed:
        return False
    if normalized_allowed.startswith("*."):
        base_domain = normalized_allowed[2:]
        return normalized_host == base_domain or normalized_host.endswith("." + base_domain)
    return normalized_host == _extract_host_raw(allowed_domain)


def host_in_allowed_domains(host: str, allowed_domains: list[str]) -> bool:
    """Return True when a host matches any allowed domain entry."""
    return any(
        host_matches_allowed_domain(host, allowed_domain) for allowed_domain in allowed_domains
    )


def extract_root_domain(domain: str) -> str:
    """
    Extracts the root domain from a full domain name.

    Args:
        domain: Full domain (e.g., 'sub.example.com')

    Returns:
        Root domain (e.g., 'example.com')
    """
    parts = normalize_host(domain).strip(".").split(".")
    if len(parts) < 2:
        return domain

    suffix = ".".join(parts[-2:])
    if suffix in _MULTI_LEVEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return suffix


def is_test_domain(host: str, allowed_root: str | None = None) -> bool:
    """
    Detects if a host is a test/dummy domain that should be filtered.

    Args:
        host: The host to check
        allowed_root: Optional allowed root domain (won't be filtered)

    Returns:
        True if host appears to be test data
    """
    host_lower = _extract_host(host).lower().strip()

    if not host_lower:
        return False

    if allowed_root and in_scope(host_lower, allowed_root):
        return False

    if host_lower in _TEST_EXACT_DOMAINS:
        return True

    if is_local_host(host_lower):
        return True

    return any(pattern in host_lower for pattern in _TEST_PATTERNS)


def filter_assets(assets: list, root_domain: str) -> list:
    """
    Filters a list of assets to only include in-scope items.

    Args:
        assets: List of asset strings (hosts/URLs)
        root_domain: The authorized root domain

    Returns:
        Filtered list of in-scope assets
    """
    filtered = []

    for asset in assets:
        if not asset or not asset.strip():
            continue

        asset_host = _extract_host(asset)
        if not asset_host:
            continue

        if is_test_domain(asset_host):
            logger.warning("Scope Guard: Discarding test asset: %s", asset)
            continue

        if in_scope(asset_host, root_domain):
            filtered.append(asset.strip())
        else:
            logger.warning("Scope Guard: Discarding out-of-scope asset: %s", asset)

    return filtered


class ScopeGuard:
    """
    Main scope validation class for PromptWall.
    """

    def __init__(self, root_domain: str):
        """
        Initialize ScopeGuard.

        Args:
            root_domain: The authorized root domain for this scan
        """
        self.root_domain = extract_root_domain(root_domain)
        self.assets_in_scope = []
        self.assets_out_of_scope = []
        self.test_assets_filtered = []

    def validate(self, asset: str) -> bool:
        """
        Validates a single asset.

        Args:
            asset: Asset to validate

        Returns:
            True if in scope, False otherwise
        """
        asset = asset.strip()
        asset_host = _extract_host(asset)

        if is_test_domain(asset_host):
            self.test_assets_filtered.append(asset)
            logger.warning("Scope Guard: Test asset filtered: %s", asset)
            return False

        if in_scope(asset_host, self.root_domain):
            self.assets_in_scope.append(asset)
            return True

        self.assets_out_of_scope.append(asset)
        logger.warning("Scope Guard: Out of scope: %s", asset)
        return False

    def get_stats(self) -> dict:
        """
        Returns validation statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "root_domain": self.root_domain,
            "in_scope": len(self.assets_in_scope),
            "out_of_scope": len(self.assets_out_of_scope),
            "test_filtered": len(self.test_assets_filtered),
            "total_validated": len(self.assets_in_scope) + len(self.assets_out_of_scope),
        }
