from cli.commands.compliance_check import _matches_target


def test_compliance_matcher_normalizes_trailing_dots_and_urls():
    assert _matches_target("https://example.com./path", "example.com")
    assert _matches_target("example.com.", "https://example.com/path")
    assert not _matches_target("evil.com", "example.com")
