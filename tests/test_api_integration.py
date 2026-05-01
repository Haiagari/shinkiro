"""
API Integration Tests - OzyRecon v8.3.2
Testing all endpoints with Advanced Auth and Scopes.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from src.core.api import app
from src.storage.database import SessionLocal, init_db
from src.storage.models import Base, Target, Scan, Subdomain, Port

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
    assert response.json()["version"] == "8.3.2"

def test_health_endpoint():
    """Verifica el endpoint de salud público."""
    # Health should work even without headers (public monitoring)
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "metrics" in response.json()

def test_knowledge_graph_endpoint():
    """Verifica la estructura del grafo v8.3.2."""
    response = client.get("/intelligence/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "metadata" in data # v8.3.2 feature

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
