"""
Smoke Tests for OzyRecon v5.7 Features - v9.0.1 Alignment
"""

import pytest
from fastapi.testclient import TestClient
from src.core.api import app
from src.validation.auth import AuthValidator
from src.utils.visual import capture_screenshot

MASTER_KEY = "ozy-admin-master-777"
client = TestClient(app)
client.headers = {"X-API-KEY": MASTER_KEY}

def test_knowledge_graph_endpoint():
    """Verifica que el endpoint del grafo exista y devuelva la estructura correcta."""
    response = client.get("/intelligence/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data

def test_auth_validator_instantiation():
    """Verifica que el validador de auth esté bien construido."""
    validator = AuthValidator()
    assert hasattr(validator, "validate")

def test_visual_utility_import():
    """Verifica que la utilidad visual sea importable."""
    assert capture_screenshot is not None
    
def test_api_version_baseline():
    """Verifica que la versión de la API sea la del baseline v9.0.1."""
    assert app.version == "9.0.1"
