import pytest
from unittest.mock import MagicMock, patch
from src.validation.auth import AuthValidator
from src.core.errors import StealthSSLError, StealthRequestError

@pytest.fixture
def auth_validator():
    return AuthValidator()

def test_auth_validator_uses_ozy_http_client(auth_validator):
    """Verifica que AuthValidator usa http_client."""
    with patch('src.validation.auth.http_client') as mock_client:
        mock_get_res = MagicMock()
        mock_get_res.status_code = 200
        mock_get_res.headers = {"Server": "Apache"}
        mock_get_res.content = b"Login Page"
        
        mock_post_res = MagicMock()
        mock_post_res.status_code = 200
        mock_post_res.content = b"Welcome Admin" # Diferente de b"Login Page"
        
        mock_client.get.return_value = mock_get_res
        mock_client.post.return_value = mock_post_res
        
        hypothesis = {
            "id": "auth-1",
            "url": "http://example.com/login",
            "type": "DEFAULT_AUTH"
        }
        
        result = auth_validator.validate(hypothesis)
        
        assert mock_client.get.called
        assert mock_client.post.called
        assert result.status == "confirmed"
        assert "Potential default credentials" in result.notes

def test_auth_validator_handles_stealth_ssl_error(auth_validator):
    """Verifica el manejo de StealthSSLError en AuthValidator."""
    with patch('src.validation.auth.http_client') as mock_client:
        mock_client.get.side_effect = StealthSSLError("SSL Error")
        
        hypothesis = {"id": "auth-ssl", "url": "https://expired.com", "type": "DEFAULT_AUTH"}
        result = auth_validator.validate(hypothesis)
        
        assert result.status == "failed_validation"
        assert "SSL Error" in result.notes
