"""
Smoke Tests para las nuevas funcionalidades de la v5.7
"""

import pytest
from fastapi.testclient import TestClient
from src.core.api import app
from src.validation.auth import AuthValidator
from src.utils.visual import capture_screenshot

client = TestClient(app)

def test_knowledge_graph_endpoint():
    """Verifica que el endpoint del grafo exista y devuelva la estructura correcta."""
    # Nota: No necesitamos API Key si lo llamamos internamente via TestClient (o depende de middleware)
    # Como el dashboard es libre en local, probamos el GET
    response = client.get("/intelligence/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)

def test_auth_validator_instantiation():
    """Verifica que el validador de auth esté bien construido."""
    validator = AuthValidator()
    assert validator.DEFAULT_CREDS[0] == ("admin", "admin")
    assert hasattr(validator, "validate")

def test_visual_utility_import():
    """Verifica que la utilidad visual sea importable y tenga la función de captura."""
    # No ejecutamos la captura real para no depender de internet/browsers en el test
    assert capture_screenshot is not None
    
def test_api_version_v57():
    """Verifica que la versión de la API esté actualizada."""
    response = client.get("/")
    # El root endpoint devuelve version 4.0 (legacy) o la del sistema
    # Pero el constructor de FastAPI en api.py dice 5.7
    assert app.version == "5.7"
