import pytest
from src.core.errors import StealthSSLError, StealthRequestError, OzyReconError

def test_stealth_exceptions_exist():
    # Este test fallará porque StealthSSLError y StealthRequestError no existen aún
    with pytest.raises(StealthSSLError):
        raise StealthSSLError("SSL fail")
    
    with pytest.raises(StealthRequestError):
        raise StealthRequestError("Request fail")

def test_stealth_exceptions_inheritance():
    assert issubclass(StealthSSLError, OzyReconError)
    assert issubclass(StealthRequestError, OzyReconError)
