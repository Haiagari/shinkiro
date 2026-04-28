from src.validation.policy import validation_policy


def test_validation_policy_classifies_safe_http():
    decision = validation_policy.classify({
        "type": "EXPOSED_VERSION",
        "url": "http://example.com",
    })

    assert decision.action == "safe"
    assert decision.is_safe


def test_validation_policy_classifies_sensitive_path_as_gate():
    decision = validation_policy.classify({
        "type": "DEFAULT_AUTH",
        "url": "http://admin.example.com",
    })

    assert decision.action == "gate_required"
    assert decision.requires_gate


def test_validation_policy_blocks_missing_url():
    decision = validation_policy.classify({
        "type": "EXPOSED_VERSION",
        "url": "",
    })

    assert decision.action == "blocked"
    assert decision.is_blocked


def test_validation_policy_blocks_private_scope():
    decision = validation_policy.classify({
        "type": "EXPOSED_VERSION",
        "url": "http://127.0.0.1:8080",
    })

    assert decision.action == "blocked"
    assert "not allowed" in decision.reason
