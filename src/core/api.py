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
from src.storage.database import SessionLocal
from src.intelligence.learning_orchestrator import learning_orchestrator
from src.intelligence.sync_manager import sync_manager
from src.core.tool_manager import tool_manager
from src.core.config import config

app = FastAPI(title="OzyRecon API", version="4.0")

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
        queries = DBQueries(db)
        targets = db.query(queries.models.Target).all()
        return [{"id": t.id, "domain": t.domain, "added_at": t.added_at} for t in targets]
    finally:
        db.close()

@app.get("/targets/{domain}/latest")
def get_latest_scan(domain: str):
    """Obtiene el último resultado normalizado de un target."""
    from src.export.normalizer import exporter
    db = SessionLocal()
    try:
        queries = DBQueries(db)
        latest = queries.get_latest_scan(domain)
        if not latest:
            raise HTTPException(status_code=404, detail="Target or scan not found")
        
        result = exporter.export_scan(latest.session_id, domain)
        return result.to_dict()
    finally:
        db.close()

def start_api(host: str = "0.0.0.0", port: int = 8000):
    """Arranca el servidor de la API."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
