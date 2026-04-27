import pytest
from unittest.mock import MagicMock, patch
import sys

# Mock curl_cffi para el test de integración si no está presente
# En un entorno real curl_cffi debería estar instalado para este test
try:
    from curl_cffi import requests as stealth_requests
    HAS_STEALTH = True
except ImportError:
    mock_curl_cffi = MagicMock()
    mock_curl_cffi_requests = MagicMock()
    mock_curl_cffi.requests = mock_curl_cffi_requests
    sys.modules['curl_cffi'] = mock_curl_cffi
    sys.modules['curl_cffi.requests'] = mock_curl_cffi_requests
    HAS_STEALTH = False

from src.core.providers.http_clients import OzyHTTPClient
from src.opsec.chameleon import ChameleonEngine

def test_ja3_fingerprint_consistency():
    """
    Verifica que el JA3 del cliente coincida con el perfil seleccionado.
    Mockeamos la respuesta del servidor de fingerprinting para validar que los headers/settings se envían bien.
    """
    with patch('src.core.providers.http_clients.HAS_STEALTH', True):
        # 1. Preparar el mock del motor chameleon para devolver un perfil específico
        with patch('src.opsec.chameleon.chameleon.generate_identity') as mock_gen:
            mock_identity = MagicMock()
            mock_identity.tls_profile = 'firefox'
            mock_identity.headers = {'User-Agent': 'Mock-Firefox'}
            mock_gen.return_value = mock_identity
            
            client = OzyHTTPClient()
            
            # 2. Mockear la sesión de curl_cffi
            with patch('src.core.providers.http_clients.stealth_requests.Session') as mock_session_class:
                mock_session = MagicMock()
                mock_session_class.return_value = mock_session
                # Re-vincular la sesión en la instancia del cliente para el test
                client.session = mock_session
                
                # Mockear la respuesta del servidor de JA3
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "ja3_hash": "771", # Fingerprint simplificado para el mock
                    "user_agent": "Mock-Firefox"
                }
                mock_session.request.return_value = mock_response
                
                # 3. Realizar la petición
                res = client.get("https://tls.browserleaks.com/json")
                
                # 4. Validar que se pasó el perfil correcto a curl_cffi
                args, kwargs = mock_session.request.call_args
                assert kwargs['impersonate'] == 'firefox', "Debería haber pasado 'firefox' al motor"
                assert kwargs['headers']['User-Agent'] == 'Mock-Firefox', "User-Agent no coincide"
                
                # 5. Validar consistencia en un perfil 'chrome' (mapeo a chrome124)
                mock_identity.tls_profile = 'chrome'
                mock_identity.headers = {'User-Agent': 'Mock-Chrome'}
                
                client.get("https://tls.browserleaks.com/json")
                args, kwargs = mock_session.request.call_args
                assert kwargs['impersonate'] == 'chrome124', "Debería haber mapeado 'chrome' a 'chrome124'"
