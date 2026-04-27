import pytest
import sys
from unittest.mock import MagicMock, patch

# Mock curl_cffi before importing anything that might use it
mock_curl_cffi = MagicMock()
mock_curl_cffi_requests = MagicMock()
mock_curl_cffi.requests = mock_curl_cffi_requests
sys.modules['curl_cffi'] = mock_curl_cffi
sys.modules['curl_cffi.requests'] = mock_curl_cffi_requests

from src.core.providers.http_clients import OzyHTTPClient
from src.core.errors import StealthSSLError, StealthRequestError
import certifi

def test_ozy_http_client_uses_session():
    client = OzyHTTPClient()
    assert hasattr(client, 'session')

def test_ozy_http_client_request_parameters():
    mock_session_instance = MagicMock()
    mock_session_instance.request.return_value = MagicMock(status_code=200)
    mock_curl_cffi_requests.Session.return_value = mock_session_instance
    
    # Reload or re-instantiate to use the mocked session
    client = OzyHTTPClient()
    client.session = mock_session_instance 
    
    client.request("GET", "https://example.com", impersonate="chrome")
    
    args, kwargs = mock_session_instance.request.call_args
    assert kwargs['verify'] == certifi.where()
    assert kwargs['impersonate'] == "chrome124"

def test_ozy_http_client_handles_ssl_error():
    # Define a dummy exception class to simulate curl_cffi.requests.errors.RequestsError
    class DummyRequestsError(Exception):
        pass
    
    mock_curl_cffi_requests.errors = MagicMock()
    mock_curl_cffi_requests.errors.RequestsError = DummyRequestsError
    
    mock_session_instance = MagicMock()
    mock_session_instance.request.side_effect = DummyRequestsError("SSL certificate problem")
    mock_curl_cffi_requests.Session.return_value = mock_session_instance
    
    client = OzyHTTPClient()
    client.session = mock_session_instance
    
    with pytest.raises(StealthSSLError) as excinfo:
        client.request("GET", "https://expired.badssl.com")
    
    assert "SSL certificate problem" in str(excinfo.value)

def test_ozy_http_client_handles_generic_request_error():
    mock_session_instance = MagicMock()
    mock_session_instance.request.side_effect = Exception("Connection refused")
    mock_curl_cffi_requests.Session.return_value = mock_session_instance
    
    client = OzyHTTPClient()
    client.session = mock_session_instance
    
    with pytest.raises(StealthRequestError) as excinfo:
        client.request("GET", "https://offline.target")
    
    assert "Connection refused" in str(excinfo.value)

def test_ozy_http_client_verify_override():
    mock_session_instance = MagicMock()
    mock_session_instance.request.return_value = MagicMock(status_code=200)
    mock_curl_cffi_requests.Session.return_value = mock_session_instance
    
    client = OzyHTTPClient()
    client.session = mock_session_instance
    
    client.request("GET", "https://example.com", verify=False)
    
    args, kwargs = mock_session_instance.request.call_args
    assert kwargs['verify'] is False
