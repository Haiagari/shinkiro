"""
API Integration Tests - PromptWall v9.0.1
Testing all endpoints with Advanced Auth and Scopes.
"""

import pytest

from fastapi.testclient import TestClient

from src.core.api import app
from src.storage.database import init_db

# Initialize DB for tests
init_db()

# Test configuration
MASTER_KEY = "ozy-admin-master-777"
client = TestClient(app)
client.headers = {"X-API-KEY": MASTER_KEY}


def test_root_endpoint():
    """Verifica que el endpoint raíz responda con la versión correcta."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["version"] == "9.0.1"


def test_health_endpoint():
    """Verifica el endpoint de salud público."""
    # Health should work even without headers (public monitoring)
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "metrics" in response.json()


def test_knowledge_graph_endpoint():
    """Verifica la estructura del grafo v9.0.1."""
    response = client.get("/intelligence/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "metadata" in data  # v9.0.1 feature


def test_targets_endpoint():
    """Verifica la lista de targets."""
    response = client.get("/targets")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_sessions_endpoint():
    """Verifica el listado de sesiones."""
    response = client.get("/sessions")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_unauthorized_access():
    """Verifica que sin key se rechace el acceso a endpoints protegidos."""
    bad_client = TestClient(app)
    response = bad_client.get("/sessions")
    assert response.status_code == 403
    assert "Unauthorized" in response.json()["detail"]


def test_hunt_endpoint_auth():
    """Verifica que el endpoint /hunt requiera auth admin."""
    response = client.post("/hunt", json={"target": "test.com", "dry_run": True})
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_ssrf_protection_api():
    """Verifica que la API bloquee targets internos."""
    response = client.post("/hunt", json={"target": "127.0.0.1"})
    assert response.status_code == 400
    assert "restricted" in response.json()["detail"]


def test_hunt_endpoint_blocks_localhost_aliases():
    """Verifica que /hunt bloquee aliases locales comunes."""
    response = client.post("/hunt", json={"target": "localhost"})
    assert response.status_code == 400
    assert "restricted" in response.json()["detail"]


def test_hunt_endpoint_blocks_private_ips():
    """Verifica que /hunt bloquee IPs privadas con el validador compartido."""
    response = client.post("/hunt", json={"target": "10.0.0.5"})
    assert response.status_code == 400
    assert "restricted" in response.json()["detail"]


@pytest.mark.parametrize("target", [None, True, False, 123])
def test_hunt_endpoint_rejects_non_string_targets(target):
    """Verifica que /hunt rechace targets que no sean strings."""
    response = client.post("/hunt", json={"target": target})
    assert response.status_code == 400
    assert "non-empty string" in response.json()["detail"]


def test_hunt_endpoint_blocks_ipv6_private_targets():
    """Verifica que /hunt bloquee IPv6 privadas con el validador compartido."""
    response = client.post("/hunt", json={"target": "fd00::1"})
    assert response.status_code == 400
    assert "restricted" in response.json()["detail"]
