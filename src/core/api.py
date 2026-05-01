"""
OzyRecon API - Swarm Control & Data Exposure
v8.3.2 - Enterprise Baseline Edition
"""

import logging
import uuid
import asyncio
import re
import json
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Body, Depends, Header, BackgroundTasks, Security, Request
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.core.logging import get_logger
from src.storage.queries import DBQueries
from src.storage.db_queries import get_latest_scan as db_get_latest_scan
from src.storage.database import SessionLocal
from src.storage.models import Target, Subdomain, Scan
from src.intelligence.ai_analyzer import ai_analyst
from src.intelligence.graph_builder import graph_builder
from src.modes.hunt import HuntMode
from src.security.target_validator import is_safe_target
from src.core.session_manager import session_manager
from src.auth.dependencies import require_scope, get_current_key
from src.auth.rate_limit import rate_limit_dependency
from src.auth.audit import audit_logger
from src.intelligence.autonomy import build_autonomy_plan

app = FastAPI(title="OzyRecon API", version="8.3.2")
logger = get_logger("api")

# --- AUTHENTICATION ---
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

# --- CONCURRENCY & METRICS ---
scan_semaphore = asyncio.Semaphore(10)

class Metrics:
    scans_total = 0
    scans_failed = 0
    start_time = datetime.now()
    history = []

    @classmethod
    def record_scan(cls, success=True):
        cls.scans_total += 1
        if not success: cls.scans_failed += 1
        cls.history.append(datetime.now())

    @classmethod
    def get_recent_count(cls):
        five_mins_ago = datetime.now() - timedelta(minutes=5)
        cls.history = [t for t in cls.history if t > five_mins_ago]
        return len(cls.history)

# --- MAINTENANCE v8.2 ---
async def _cleanup_storage_task():
    while True:
        try:
            ttl_days = 7
            cutoff = datetime.now() - timedelta(days=ttl_days)
            runs_dir = Path("runs")
            if runs_dir.exists():
                for session_dir in runs_dir.iterdir():
                    if session_dir.is_dir() and datetime.fromtimestamp(session_dir.stat().st_mtime) < cutoff:
                        shutil.rmtree(session_dir)
        except: pass
        await asyncio.sleep(3600)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_cleanup_storage_task())

# --- UTILS ---
def _sanitize_api_target(target: str) -> str:
    if not target: return ""
    return re.sub(r"[;&|`$<>^{}\[\]\s]", "", target)

async def _run_hunt_task(session_id: str, target: str, options: dict):
    async with scan_semaphore:
        try:
            if options.get("slow"): await asyncio.sleep(10)
            mode = HuntMode(target, options=options)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, mode.run)
            Metrics.record_scan(success=True)
        except asyncio.CancelledError:
            Metrics.record_scan(success=False)
            raise
        except Exception as e:
            logger.error(f"Background hunt failed: {e}")
            Metrics.record_scan(success=False)
        finally:
            session_manager.unregister_task(session_id)

# --- CORE LOGIC FUNCTIONS ---
def get_session_trace(session_id: str):
    db = SessionLocal()
    try: return DBQueries(db).get_session_trace(session_id)
    finally: db.close()

def get_autonomy_plan(target: str):
    db = SessionLocal()
    try: 
        plan = build_autonomy_plan(db, target)
        if not plan: raise HTTPException(status_code=404, detail="Target not found")
        return plan
    except ValueError as e:
        # v8.3.2 - Explicitly raise HTTPException for test compatibility
        raise HTTPException(status_code=404, detail=str(e))
    finally: db.close()

def get_latest_scan(domain: str):
    from src.export.normalizer import NormalizedExporter
    db = SessionLocal()
    try:
        latest = db_get_latest_scan(db, domain)
        if not latest: return None
        return NormalizedExporter(db).export_scan(latest.session_id, domain).to_dict()
    finally: db.close()

# --- ENDPOINTS ---
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

scan_deduplicator: Dict[str, tuple] = {}

def _generate_idempotency_key(key_name: str, target: str, payload: dict) -> str:
    seed = f"{key_name}:{target}:{payload.get('dry_run')}:{payload.get('speed')}"
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()

@app.get("/health")
def health_check():
    return {
        "status": "ok", "version": "8.3.2",
        "metrics": {
            "uptime_seconds": int((datetime.now() - Metrics.start_time).total_seconds()),
            "scans_last_5m": Metrics.get_recent_count(),
            "scans_total": Metrics.scans_total,
            "concurrency": {"max": 10, "active": 10 - scan_semaphore._value}
        }
    }

@app.get("/")
def read_root():
    return {"status": "online", "platform": "OzyRecon", "version": "8.3.2"}

@app.post("/hunt")
async def start_hunt(
    request: Request, background_tasks: BackgroundTasks, payload: Dict[str, Any] = Body(...),
    identity: Dict = Depends(require_scope("admin:*")), _rate_limit: Any = Depends(rate_limit_dependency)
):
    audit_logger.log_action(request, identity, "hunt:run")
    raw_target = payload.get("target")
    if not raw_target: raise HTTPException(status_code=400, detail="Target required")
    target = _sanitize_api_target(raw_target)
    
    idempotency_key = _generate_idempotency_key(identity.get("name", "anon"), target, payload)
    if idempotency_key in scan_deduplicator:
        old_session, old_time = scan_deduplicator[idempotency_key]
        if datetime.now() < old_time + timedelta(minutes=5):
            return {"status": "already_running", "session_id": old_session, "target": target}

    safe, reason = is_safe_target(target)
    if not safe: raise HTTPException(status_code=400, detail=f"Target restricted: {reason}")
    
    session_id = str(uuid.uuid4())
    scan_deduplicator[idempotency_key] = (session_id, datetime.now())
    options = {"dry_run": payload.get("dry_run", False), "slow": payload.get("slow", False), "threads": payload.get("threads", 10), "session_id_override": session_id}
    
    task = asyncio.create_task(_run_hunt_task(session_id, target, options))
    session_manager.register_task(session_id, task)
    return {"status": "accepted", "session_id": session_id, "target": target, "authorized_by": identity.get("name")}

@app.get("/sessions/{session_id}/trace")
async def api_get_session_trace(session_id: str, identity: Dict = Depends(get_current_key)):
    trace = get_session_trace(session_id)
    if not trace: raise HTTPException(status_code=404, detail="Session not found")
    return trace

@app.get("/intelligence/autonomy")
async def api_get_autonomy_plan(target: str, identity: Dict = Depends(require_scope("admin:*"))):
    try:
        plan = get_autonomy_plan(target)
        if not plan: raise HTTPException(status_code=404, detail="Target not found")
        return plan
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/targets")
def list_targets(identity: Dict = Depends(get_current_key)):
    """Lista todos los targets conocidos (v8.3.2 restored)."""
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        return [{"id": t.id, "domain": t.domain, "added_at": t.added_at} for t in targets]
    finally:
        db.close()

@app.get("/targets/{domain}/latest")
async def api_get_latest_scan(domain: str, identity: Dict = Depends(get_current_key)):
    result = get_latest_scan(domain)
    if not result: raise HTTPException(status_code=404, detail="No scan found")
    return result

@app.get("/sessions")
def list_sessions(request: Request, identity: Dict = Depends(get_current_key)):
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.start_time.desc()).all()
        return [{"session_id": s.session_id, "target": s.target.domain if s.target else "unknown", "status": s.status} for s in scans]
    finally: db.close()

@app.get("/intelligence/graph")
def get_knowledge_graph(target: Optional[str] = None, identity: Dict = Depends(get_current_key)):

    db = SessionLocal()
    try:
        query = db.query(Scan).order_by(Scan.start_time.desc())
        if target:
            target_obj = db.query(Target).filter(Target.domain == target).first()
            if not target_obj: raise HTTPException(status_code=404, detail="Target not found")
            query = query.filter(Scan.target_id == target_obj.id)
        scan = query.first()
        return graph_builder.build_scan_graph(db, scan.id) if scan else {"nodes": [], "edges": []}
    finally: db.close()

def start_api(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)
