"""Helpers for canonical scan-target normalization."""

from __future__ import annotations

from urllib.parse import urlparse

from src.validation.policy import normalize_target_url


def first_token(raw_value: str | None) -> str:
    """Return the first whitespace-delimited token from a raw value."""
    if not raw_value:
        return ""

    value = raw_value.strip()
    if not value:
        return ""

    return value.split(maxsplit=1)[0]


def normalize_lookup_target(raw_target: str) -> str:
    """Return a canonical hostname for storage lookups."""
    host = extract_target_host(first_token(raw_target))
    return host.rstrip(".")


def normalize_base_target(raw_target: str) -> str:
    """Return a canonical scheme://host[:port] target string."""
    normalized = normalize_target_url(raw_target.strip())
    if not normalized:
        return normalized

    parsed = urlparse(normalized)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"

    return normalized.rstrip("/")


def extract_target_host(raw_target: str) -> str:
    """Return the hostname portion of a raw target or URL."""
    normalized = normalize_target_url(raw_target.strip())
    if not normalized:
        return ""

    parsed = urlparse(normalized)
    return parsed.hostname or ""


__all__ = [
    "extract_target_host",
    "first_token",
    "normalize_base_target",
    "normalize_lookup_target",
]
