"""
OzyRecon API - Control de Enjambre y Exposición de Datos
Basado en FastAPI para alto rendimiento.
"""

from fastapi import FastAPI, HTTPException, Body, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Dict, Any, List, Optional
from pathlib import Path
from src.storage.queries import DBQueries
from src.storage.db_queries import get_latest_scan as db_get_latest_scan
from src.storage.database import SessionLocal
from src.intelligence.learning_orchestrator import learning_orchestrator
from src.intelligence.sync_manager import sync_manager
from src.core.tool_manager import tool_manager
from src.core.config import config
from src.storage.models import Hypothesis, Evidence, Target, Port, Subdomain, Scan
from src.workflow.states import WorkflowState, Actor

from src.gate.manager import gate_manager
from src.intelligence.autonomy import build_autonomy_plan
from src.intelligence.graph_builder import graph_builder

app = FastAPI(title="OzyRecon API", version="7.0.0-alpha.1")

# Montar archivos estáticos para el dashboard
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/health")
def health_check():
    """Endpoint para validación de salud del motor."""
    return {"status": "ok", "engine": "OzyRecon", "version": "7.0.0-alpha.1"}

@app.get("/dashboard")
async def get_dashboard():
    return FileResponse(str(static_path / "index.html"))

@app.get("/")
def read_root():
    return {"status": "online", "platform": "OzyRecon", "version": "7.0.0-alpha.1"}

@app.get("/intelligence/status")
def get_intel_status():
    """Retorna el estado mental actual del nodo."""
    return learning_orchestrator.get_full_feedback()

# ══════════════════════════════════════════════════════════════════════════════
# HUMAN GATE & VALIDATION ENDPOINTS v5.6
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/gate/pending")
def get_pending_hypotheses():
    """Retorna las hipótesis esperando aprobación."""
    return gate_manager.list_pending()

@app.post("/gate/approve/{hyp_id}")
def approve_hypothesis(hyp_id: str, reason: Optional[str] = "Approved via Web Dashboard"):
    """Aprueba una hipótesis para validación."""
    success = gate_manager.approve(hyp_id, notes=reason)
    if not success:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"status": "approved", "id": hyp_id}

@app.post("/gate/reject/{hyp_id}")
def reject_hypothesis(hyp_id: str, reason: Optional[str] = "Rejected via Web Dashboard"):
    """Rechaza una hipótesis."""
    success = gate_manager.reject(hyp_id, reason=reason)
    if not success:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"status": "rejected", "id": hyp_id}

@app.get("/evidence/{hyp_id}")
def get_evidence(hyp_id: str):
    """Obtiene evidencia técnica para una hipótesis."""
    from src.evidence.engine import evidence_engine
    evs = evidence_engine.get_evidence_for_hypothesis(hyp_id)
    return [
        {
            "id": e.id,
            "type": e.type,
            "data": e.data,
            "timestamp": e.timestamp.isoformat(),
            "hash": e.hash_sha256,
            "metadata": e.metadata_json or {},
        } for e in evs
    ]

@app.get("/intelligence/export")
def export_intel():
    """Exporta el cerebro para sincronización."""
    path = sync_manager.export_brain()
    return {"status": "exported", "file": str(path)}

@app.get("/intelligence/autonomy")
def get_autonomy_plan(target: str):
    """Genera un plan seguro de autonomía para un target."""
    db = SessionLocal()
    try:
        return build_autonomy_plan(db, target)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        db.close()

@app.get("/targets")
def list_targets():
    """Lista todos los targets conocidos por este nodo."""
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        return [{"id": t.id, "domain": t.domain, "added_at": t.added_at} for t in targets]
    finally:
        db.close()

@app.get("/targets/{domain}/latest")
def get_latest_scan(domain: str):
    """Obtiene el último resultado normalizado de un target."""
    from src.export.normalizer import NormalizedExporter
    db = SessionLocal()
    try:
        latest = db_get_latest_scan(db, domain)
        if not latest:
            raise HTTPException(status_code=404, detail="Target or scan not found")
        
        result = NormalizedExporter(db).export_scan(latest.session_id, domain)
        return result.to_dict()
    finally:
        db.close()

@app.get("/sessions/{session_id}/trace")
def get_session_trace(session_id: str):
    """Devuelve un trazado consolidado de sesión para observabilidad."""
    db = SessionLocal()
    try:
        trace = DBQueries(db).get_session_trace(session_id)
        if not trace:
            raise HTTPException(status_code=404, detail="Session not found")
        return trace
    finally:
        db.close()

@app.get("/intelligence/graph")
def get_knowledge_graph(target: Optional[str] = None):
    """
    Genera el Knowledge Graph v7 basado en relaciones reales.
    """
    db = SessionLocal()
    try:
        # Si no hay target, buscamos el último scan global
        if target:
            target_obj = db.query(Target).filter(Target.domain == target).first()
            if not target_obj:
                raise HTTPException(status_code=404, detail="Target not found")
            scan = db.query(Scan).filter(Scan.target_id == target_obj.id).order_by(Scan.start_time.desc()).first()
        else:
            scan = db.query(Scan).order_by(Scan.start_time.desc()).first()
        
        if not scan:
            return {"nodes": [], "edges": []}
            
        return graph_builder.build_scan_graph(db, scan.id)
    finally:
        db.close()

@app.get("/scans/{scan_id}/graph")
def get_scan_graph(scan_id: int):
    """Devuelve el grafo de relaciones para un scan específico."""
    db = SessionLocal()
    try:
        return graph_builder.build_scan_graph(db, scan_id)
    finally:
        db.close()

def start_api(host: str = "0.0.0.0", port: int = 8000):

    """Arranca el servidor de la API."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
