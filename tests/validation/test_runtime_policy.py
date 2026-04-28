from unittest.mock import MagicMock, patch

from src.validation.auth import AuthValidator
from src.validation.http import HTTPValidator


def test_http_validator_blocks_private_scope_before_request():
    validator = HTTPValidator()

    with patch("src.validation.http.http_client.get") as mock_get:
        result = validator.validate({
            "id": "hyp-1",
            "type": "EXPOSED_VERSION",
            "url": "http://127.0.0.1:8080",
            "confidence": 0.6,
        })

    assert result.status == "inconclusive"
    assert "Blocked by policy" in result.notes
    mock_get.assert_not_called()


def test_auth_validator_requires_explicit_approval():
    validator = AuthValidator()

    with patch("src.validation.auth.http_client.get") as mock_get, \
         patch("src.validation.auth.http_client.post") as mock_post:
        result = validator.validate({
            "id": "hyp-2",
            "type": "DEFAULT_AUTH",
            "url": "https://auth.example.com/login",
            "confidence": 0.5,
        })

    assert result.status == "inconclusive"
    assert "Gate required" in result.notes
    mock_get.assert_not_called()
    mock_post.assert_not_called()
