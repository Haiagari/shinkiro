from src.validation.policy import normalize_target_url, validation_policy


def test_validation_policy_classifies_safe_http():
    decision = validation_policy.classify(
        {
            "type": "EXPOSED_VERSION",
            "url": "http://example.com",
        }
    )

    assert decision.action == "safe"
    assert decision.is_safe


def test_validation_policy_classifies_sensitive_path_as_gate():
    decision = validation_policy.classify(
        {
            "type": "DEFAULT_AUTH",
            "url": "http://admin.example.com",
        }
    )

    assert decision.action == "gate_required"
    assert decision.requires_gate


def test_validation_policy_blocks_missing_url():
    decision = validation_policy.classify(
        {
            "type": "EXPOSED_VERSION",
            "url": "",
        }
    )

    assert decision.action == "blocked"
    assert decision.is_blocked


def test_validation_policy_blocks_private_scope():
    decision = validation_policy.classify(
        {
            "type": "EXPOSED_VERSION",
            "url": "http://127.0.0.1:8080",
        }
    )

    assert decision.action == "blocked"
    assert "restricted" in decision.reason


def test_validation_policy_blocks_ipv4_mapped_ipv6_scope():
    decision = validation_policy.classify(
        {
            "type": "EXPOSED_VERSION",
            "url": "http://[::ffff:127.0.0.1]:8080",
        }
    )

    assert decision.action == "blocked"
    assert "restricted" in decision.reason


def test_validation_policy_honors_scope_yaml_before_shared_validator(tmp_path, monkeypatch):
    scope_dir = tmp_path / "config"
    scope_dir.mkdir()
    (scope_dir / "scope.yaml").write_text(
        "allowed_domains:\n  - allowed.example.com\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "src.validation.policy.is_safe_target", lambda host: (False, "blocked-by-shared-validator")
    )

    decision = validation_policy.scope_decision("https://allowed.example.com")

    assert decision.action == "safe"
    assert "explicitly allowed" in decision.reason


def test_validation_policy_honors_wildcard_scope_yaml(tmp_path, monkeypatch):
    scope_dir = tmp_path / "config"
    scope_dir.mkdir()
    (scope_dir / "scope.yaml").write_text(
        'allowed_domains:\n  - "*.allowed.example.com"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "src.validation.policy.is_safe_target", lambda host: (False, "blocked-by-shared-validator")
    )

    decision = validation_policy.scope_decision("https://api.allowed.example.com")

    assert decision.action == "safe"
    assert "explicitly allowed" in decision.reason


def test_normalize_target_url_prefers_https_for_raw_hosts():
    assert normalize_target_url("api.example.com:8443") == "https://api.example.com:8443"


def test_normalize_target_url_preserves_existing_scheme():
    assert normalize_target_url("http://api.example.com:8080") == "http://api.example.com:8080"
