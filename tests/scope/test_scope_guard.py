import pytest

from src.scope import (
    ScopeGuard,
    extract_root_domain,
    filter_assets,
    host_in_allowed_domains,
    is_test_domain,
    normalize_host,
    validate_url,
)


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1", "::ffff:127.0.0.1", "10.0.0.1", "fd00::1"],
)
def test_is_test_domain_blocks_local_and_reserved_hosts(host):
    assert is_test_domain(host)


def test_is_test_domain_preserves_allowed_root_assets():
    assert not is_test_domain("api.example.com", "example.com")


def test_validate_url_accepts_host_with_port():
    assert validate_url("https://api.example.com:443/path", "example.com")
    assert validate_url("https://api.example.com./path", "example.com.")


def test_normalize_host_strips_common_prefixes():
    assert normalize_host("www.api.example.com") == "api.example.com"
    assert normalize_host("api.example.com.") == "api.example.com"


def test_extract_root_domain_handles_public_suffixes():
    assert extract_root_domain("sub.example.co.uk") == "example.co.uk"
    assert extract_root_domain("sub.example.co.uk.") == "example.co.uk"


def test_scope_guard_preserves_public_suffix_scope():
    guard = ScopeGuard("sub.example.co.uk")

    assert guard.root_domain == "example.co.uk"
    assert guard.validate("api.example.co.uk")
    assert not guard.validate("attacker.co.uk")


def test_host_in_allowed_domains_supports_wildcards():
    assert host_in_allowed_domains("api.example.com", ["*.example.com"])
    assert host_in_allowed_domains("example.com", ["*.example.com"])


def test_host_in_allowed_domains_requires_exact_match_for_exact_entries():
    assert host_in_allowed_domains("www.example.com", ["www.example.com"])
    assert host_in_allowed_domains("https://www.example.com:8443/path", ["www.example.com"])
    assert host_in_allowed_domains("www.example.com.", ["www.example.com"])
    assert host_in_allowed_domains("www.example.com.", ["www.example.com."])
    assert not host_in_allowed_domains("example.com", ["www.example.com"])
    assert not host_in_allowed_domains("attacker.example.com", ["www.example.com"])


def test_filter_assets_removes_local_hosts():
    assets = [
        "https://api.example.com:443/path",
        "localhost",
        "127.0.0.1",
        "evil-corp.com",
    ]

    filtered = filter_assets(assets, "example.com")

    assert filtered == ["https://api.example.com:443/path"]
