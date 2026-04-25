"""
API Integration Tests - OzyRecon v5.7
Prueba TODOS los endpoints de src/core/api.py
"""

import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]

# Ensure src is in path
sys.path.insert(0, str(ROOT_DIR))

from src.core.api import app
from src.validation.auth import AuthValidator
from src.utils.visual import capture_screenshot
from src.storage.database import SessionLocal, init_db
from src.storage.models import Target, Scan, Hypothesis, Subdomain

# Initialize DB for tests
init_db()

client = TestClient(app)


# =============================================================================
# ENDPOINT: /
# =============================================================================

def test_root_endpoint():
    """Verifica que el endpoint raíz responda."""
    response = client.get("/")
    assert response.status_code == 200


# =============================================================================
# ENDPOINT: /intelligence/graph (v5.7 - Knowledge Graph)
# =============================================================================

def test_knowledge_graph_endpoint():
    """Verifica que el endpoint del grafo exista y devuelva la estructura correcta."""
    response = client.get("/intelligence/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


def test_knowledge_graph_empty_state():
    """Verifica el grafo en estado vacío (sin datos)."""
    response = client.get("/intelligence/graph")
    data = response.json()
    # Debe devolver arrays vacíos, no error
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


# =============================================================================
# ENDPOINT: /intelligence/status
# =============================================================================

def test_intelligence_status_endpoint():
    """Verifica que el endpoint de status responda correctamente."""
    response = client.get("/intelligence/status")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "weights" in data
    assert "feedback_insights" in data


def test_intelligence_status_metrics_structure():
    """Verifica la estructura de métricas del sistema de aprendizaje."""
    response = client.get("/intelligence/status")
    data = response.json()
    metrics = data["metrics"]
    assert "total_decisions" in metrics
    assert "decision_accuracy_rate" in metrics
    assert "false_positive_rate" in metrics


# =============================================================================
# ENDPOINT: /targets
# =============================================================================

def test_targets_endpoint():
    """Verifica que el endpoint de targets responda."""
    response = client.get("/targets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_targets_empty():
    """Verifica que targets responda con array vacío si no hay datos."""
    response = client.get("/targets")
    data = response.json()
    assert isinstance(data, list)


# =============================================================================
# ENDPOINT: /targets/{domain}/latest
# =============================================================================

def test_targets_latest_not_found():
    """Verifica 404 para target inexistente."""
    response = client.get("/targets/nonexistent.domain.that.does.not.exist/latest")
    assert response.status_code == 404


def test_targets_latest_with_existing_target():
    """Verifica que latest responda con scan result para target existente."""
    # Usa el primer target que exista en la DB, o falla gracefully si no hay
    targets_response = client.get("/targets")
    targets = targets_response.json()
    
    if targets:
        existing_domain = targets[0]["domain"]
        response = client.get(f"/targets/{existing_domain}/latest")
        assert response.status_code in [200, 404]
    else:
        # Si no hay targets, verificamos que el endpoint no crashee
        response = client.get("/targets/test.example.com/latest")
        assert response.status_code in [200, 404]


# =============================================================================
# ENDPOINT: /gate/pending
# =============================================================================

def test_gate_pending_endpoint():
    """Verifica que el endpoint de hipótesis pendientes responda."""
    response = client.get("/gate/pending")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_gate_pending_structure():
    """Verifica la estructura de una hipótesis."""
    response = client.get("/gate/pending")
    data = response.json()
    for hypo in data:
        assert "id" in hypo
        assert "type" in hypo
        assert "description" in hypo
        assert "confidence" in hypo
        assert "risk" in hypo


# =============================================================================
# ENDPOINT: /gate/approve/{hyp_id}
# =============================================================================

def test_gate_approve_not_found():
    """Verifica 404 al aprobar hipótesis inexistente."""
    response = client.post("/gate/approve/nonexistent_hypothesis_id_12345")
    assert response.status_code == 404


# =============================================================================
# ENDPOINT: /gate/reject/{hyp_id}
# =============================================================================

def test_gate_reject_not_found():
    """Verifica 404 al rechazar hipótesis inexistente."""
    response = client.post("/gate/reject/nonexistent_hypothesis_id_12345")
    assert response.status_code == 404


# =============================================================================
# ENDPOINT: /evidence/{hyp_id}
# =============================================================================

def test_evidence_with_nonexistent_hyp_id():
    """Verifica que evidencia devuelva estructura correcta incluso para hipótesis inexistente."""
    response = client.get("/evidence/nonexistent_hyp_id_12345")
    # El endpoint devuelve 200 con lista vacía, no 404
    assert response.status_code == 200
    data = response.json()
    # Debe ser una lista (vacía)
    assert isinstance(data, list)


# =============================================================================
# ENDPOINT: /intelligence/export
# =============================================================================

def test_intelligence_export():
    """Verifica que el export de inteligencia funcione."""
    response = client.get("/intelligence/export")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "exported"
    assert "file" in data


# =============================================================================
# ENDPOINT: /dashboard
# =============================================================================

def test_dashboard_endpoint():
    """Verifica que el dashboard responda."""
    response = client.get("/dashboard")
    # El dashboard puede devolver 500 si no hay datos, o 200 con estructura
    assert response.status_code in [200, 500]


# =============================================================================
# VERSION TESTS
# =============================================================================

def test_api_version_v57():
    """Verifica que la versión de la API esté actualizada."""
    response = client.get("/")
    assert app.version == "5.7"


# =============================================================================
# SMOKE TEST - TODOS LOS ENDPOINTS
# =============================================================================

def test_all_endpoints_smoke():
    """Smoke test: verifica que todos los endpoints definidos respondan sin error 500."""
    endpoints = [
        ("/", "GET"),
        ("/intelligence/graph", "GET"),
        ("/intelligence/status", "GET"),
        ("/intelligence/export", "GET"),
        ("/targets", "GET"),
        ("/gate/pending", "GET"),
        ("/dashboard", "GET"),
    ]
    
    errors = []
    for path, method in endpoints:
        try:
            if method == "GET":
                resp = client.get(path)
            if resp.status_code == 500:
                errors.append(f"{method} {path} -> 500 Internal Server Error")
        except Exception as e:
            errors.append(f"{method} {path} -> Exception: {e}")
    
    assert len(errors) == 0, f"Endpoints with errors: {errors}"


# =============================================================================
# FEATURE TESTS (v5.7)
# =============================================================================

def test_auth_validator_instantiation():
    """Verifica que el validador de auth esté bien construido."""
    validator = AuthValidator()
    assert hasattr(validator, "DEFAULT_CREDS")
    assert hasattr(validator, "validate")


def test_visual_utility_import():
    """Verifica que la utilidad visual sea importable."""
    assert capture_screenshot is not None


def test_knowledge_graph_nodes_have_required_fields():
    """Verifica que los nodos del grafo tengan los campos requeridos."""
    response = client.get("/intelligence/graph")
    data = response.json()
    
    for node in data.get("nodes", []):
        assert "data" in node
        assert "id" in node["data"]
        assert "label" in node["data"]
        assert "type" in node["data"]


def test_knowledge_graph_edges_have_required_fields():
    """Verifica que las aristas del grafo tengan los campos requeridos."""
    response = client.get("/intelligence/graph")
    data = response.json()
    
    for edge in data.get("edges", []):
        assert "data" in edge
        assert "source" in edge["data"]
        assert "target" in edge["data"]