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
from src.storage.models import Hypothesis, Evidence, Target, Port, Subdomain
from src.workflow.states import WorkflowState, Actor

from src.gate.manager import gate_manager

app = FastAPI(title="OzyRecon API", version="5.7")


# --- SEGURIDAD: Validación de API Key ---
API_KEY = config.ozyrecon_api_key

async def verify_token(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key

# Montar archivos estáticos para el dashboard (El dashboard también necesita auth en prod, 
# pero por ahora lo dejamos libre para visualización local)
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/dashboard")
async def get_dashboard():
    return FileResponse(str(static_path / "index.html"))

@app.post("/tasks/execute", dependencies=[Depends(verify_token)])
async def execute_task(
    capability: str = Body(...),
    target: str = Body(...),
    options: Dict[str, Any] = Body(default_factory=dict)
):

    """
    Endpoint para que un nodo Cerebro mande tareas a este nodo Worker.
    """
    try:
        # El Worker ejecuta la capacidad localmente
        result = tool_manager.run_capability(capability, target, **options)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {"status": "online", "platform": "OzyRecon", "version": "4.0"}

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
            "hash": e.hash_sha256
        } for e in evs
    ]

@app.get("/intelligence/export")
def export_intel():
    """Exporta el cerebro para sincronización."""
    path = sync_manager.export_brain()
    return {"status": "exported", "file": str(path)}

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
    from src.export.normalizer import exporter
    db = SessionLocal()
    try:
        latest = db_get_latest_scan(db, domain)
        if not latest:
            raise HTTPException(status_code=404, detail="Target or scan not found")
        
        result = exporter.export_scan(latest.session_id, domain)
        return result.to_dict()
    finally:
        db.close()

@app.get("/intelligence/graph")
def get_knowledge_graph():
    """
    Genera la estructura de nodos y aristas para el Knowledge Graph (v5.7).
    Formato compatible con Cytoscape.js.
    """
    db = SessionLocal()
    try:
        nodes = []
        edges = []
        processed_targets = set()
        
        # 1. Obtener Targets
        targets = db.query(Target).all()
        for t in targets:
            nodes.append({
                "data": {"id": f"t_{t.id}", "label": t.domain, "type": "target", "color": "#3b82f6"}
            })
            
            # 2. Obtener Scans para este target
            for s in t.scans:
                # 3. Obtener Subdominios
                for sub in s.subdomains:
                    sub_id = f"sub_{sub.id}"
                    nodes.append({
                        "data": {"id": sub_id, "label": sub.domain, "type": "subdomain", "color": "#10b981"}
                    })
                    edges.append({"data": {"source": f"t_{t.id}", "target": sub_id, "label": "has_subdomain"}})
                    
                    # 4. Obtener Puertos
                    # (Buscamos por host coincidente con el subdominio en el mismo scan)
                    ports = db.query(Port).filter(Port.scan_id == s.id, Port.host == sub.domain).all()
                    for p in ports:
                        port_id = f"p_{p.id}"
                        nodes.append({
                            "data": {"id": port_id, "label": f"{p.port}/{p.protocol}", "type": "port", "color": "#f59e0b"}
                        })
                        edges.append({"data": {"source": sub_id, "target": port_id, "label": "open_port"}})
                        
                        # 5. Obtener Hipótesis vinculadas al scan y puerto (via URL o host)
                        hyps = db.query(Hypothesis).filter(Hypothesis.scan_id == s.id).all()
                        for h in hyps:
                            # Link simple por host en la URL
                            if sub.domain in (h.url or ""):
                                hyp_node_id = f"h_{h.id}"
                                nodes.append({
                                    "data": {
                                        "id": hyp_node_id, 
                                        "label": h.type, 
                                        "type": "hypothesis", 
                                        "color": "#ef4444" if h.severity == "critical" else "#f97316"
                                    }
                                })
                                edges.append({"data": {"source": port_id, "target": hyp_node_id, "label": "triggers"}})

        return {"nodes": nodes, "edges": edges}
    finally:
        db.close()

def start_api(host: str = "0.0.0.0", port: int = 8000):

    """Arranca el servidor de la API."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
