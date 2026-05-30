from types import SimpleNamespace

import pytest

from src.opsec.manager import OPSECManager


@pytest.mark.parametrize(
    "target, expected_url",
    [
        ("api.example.com:8443", "https://api.example.com:8443"),
        ("https://api.example.com:8443", "https://api.example.com:8443"),
    ],
)
def test_opsec_manager_uses_normalized_url(monkeypatch, target, expected_url):
    captured = {}

    def fake_scope_decision(url: str):
        captured["url"] = url
        return SimpleNamespace(action="safe", reason="ok")

    monkeypatch.setattr("src.opsec.manager.validation_policy.scope_decision", fake_scope_decision)
    monkeypatch.setattr("src.opsec.manager.check_kill", lambda: False)

    manager = OPSECManager(target, None)
    summary = manager.get_safety_summary()

    assert captured["url"] == expected_url
    assert summary["scope"] == "safe"
    assert summary["scope_reason"] == "ok"
