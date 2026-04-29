import pytest
from unittest.mock import MagicMock, patch
from src.validation.http import HTTPValidator
from src.core.errors import StealthSSLError, StealthRequestError

@pytest.fixture
def http_validator():
    return HTTPValidator()

def test_http_validator_uses_ozy_http_client(http_validator):
    """Verifica que HttpValidator usa el cliente HTTP de Ozy."""
    with patch('src.validation.http.http_client') as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "Apache/2.4.41"}
        mock_client.get.return_value = mock_response
        
        hypothesis = {
            "id": "test-1",
            "url": "http://example.com",
            "type": "EXPOSED_VERSION"
        }
        
        result = http_validator.validate(hypothesis)
        
        # Debe llamar al cliente unificado
        mock_client.get.assert_called_once_with("http://example.com", timeout=10)
        assert result.status == "confirmed"
        assert "Apache/2.4.41" in result.notes

def test_http_validator_handles_stealth_ssl_error(http_validator):
    """Verifica el manejo de StealthSSLError en HttpValidator."""
    with patch('src.validation.http.http_client') as mock_client:
        mock_client.get.side_effect = StealthSSLError("SSL/TLS Error: Certificate expired")
        
        hypothesis = {"id": "test-ssl", "url": "https://expired.com", "type": "EXPOSED_VERSION"}
        result = http_validator.validate(hypothesis)
        
        assert result.status == "inconclusive"
        assert "SSL/TLS Error" in result.notes
        assert result.confidence_after == 0.1

def test_http_validator_handles_stealth_request_error(http_validator):
    """Verifica el manejo de StealthRequestError."""
    with patch('src.validation.http.http_client') as mock_client:
        mock_client.get.side_effect = StealthRequestError("Request Error: Connection refused")
        
        hypothesis = {"id": "test-req", "url": "http://offline.com", "type": "EXPOSED_VERSION"}
        result = http_validator.validate(hypothesis)
        
        assert result.status == "inconclusive"
        assert "Connection refused" in result.notes
