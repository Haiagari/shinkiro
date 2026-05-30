from src.core.target_normalizer import (
    extract_target_host,
    first_token,
    normalize_base_target,
    normalize_lookup_target,
)


def test_normalize_base_target_strips_path_and_query():
    assert (
        normalize_base_target("https://api.example.com:8443/path?x=1#frag")
        == "https://api.example.com:8443"
    )


def test_extract_target_host_handles_raw_and_schemed_targets():
    assert extract_target_host("api.example.com:8443/path") == "api.example.com"
    assert extract_target_host("https://api.example.com:8443/path") == "api.example.com"


def test_first_token_strips_tool_output_prefixes():
    assert (
        first_token("https://api.example.com:8443/path [200]")
        == "https://api.example.com:8443/path"
    )
    assert first_token("single-token") == "single-token"


def test_normalize_lookup_target_handles_trailing_dots():
    assert normalize_lookup_target("https://www.example.com.:8443/path") == "www.example.com"
