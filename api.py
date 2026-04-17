"""
API REST para el Framework de Bug Bounty
Uso: uvicorn api:app --reload --port 8000
"""

from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import subprocess
import sys
from typing import List

from modules.database import get_db, SessionLocal
from modules.models import Target, Scan, Vulnerability, Subdomain

app = FastAPI(title="BugBounty Framework API", version="1.0")

# Servir archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
def index():
    return FileResponse("static/index.html")

# Helpers
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "BugBounty Framework API v1.0", "status": "online"}

@app.get("/targets")
def list_targets(db: Session = Depends(get_db_session)):
    targets = db.query(Target).all()
    return targets

@app.get("/scans/{target_id}")
def get_scans(target_id: int, db: Session = Depends(get_db_session)):
    scans = db.query(Scan).filter(Scan.target_id == target_id).order_by(Scan.start_time.desc()).all()
    return scans

@app.get("/findings")
def get_all_findings(severity: str = None, db: Session = Depends(get_db_session)):
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    return query.order_by(Vulnerability.id.desc()).all()

@app.post("/scan/{domain}")
def launch_scan(domain: str, background_tasks: BackgroundTasks):
    """
    Lanza un scan en segundo plano.
    """
    def run_process(target: str):
        subprocess.run([sys.executable, "main.py", "-t", target, "--full"])

    background_tasks.add_task(run_process, domain)
    return {"message": f"Scan para {domain} iniciado en segundo plano."}

@app.get("/stats")
def get_stats(db: Session = Depends(get_db_session)):
    by_severity = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        by_severity[sev] = db.query(Vulnerability).filter(Vulnerability.severity == sev).count()
    
    return {
        "total_targets": db.query(Target).count(),
        "total_scans": db.query(Scan).count(),
        "total_vulns": db.query(Vulnerability).count(),
        "total_subdomains": db.query(Subdomain).count(),
        "by_severity": by_severity,
    }

@app.get("/intelligence")
def get_intelligence(db: Session = Depends(get_db_session)):
    """
    Retorna scoring de targets priorizados.
    """
    # Por ahora retornar datos de DB ordenados por severidad
    vulns = db.query(Vulnerability).filter(
        Vulnerability.severity.in_(["critical", "high"])
    ).order_by(Vulnerability.severity).all()
    
    # Simular scoring
    top_targets = []
    for v in vulns[:10]:
        url = v.url or ""
        host = url.split("/")[2] if "/" in url else url
        top_targets.append({
            "host": host,
            "score": 10 if v.severity == "critical" else 7,
            "reason": f"Vuln {v.severity}: {v.name}"
        })
    
    return {"top_targets": top_targets}

@app.get("/timeline/{target}")
def get_target_timeline(target: str, db: Session = Depends(get_db_session)):
    """
    Retorna timeline de evolución de un target basado en la DB.
    """
    target_obj = db.query(Target).filter(Target.domain == target).first()
    if not target_obj: return {"error": "Target no encontrado"}
    
    scans = db.query(Scan).filter(Scan.target_id == target_obj.id).order_by(Scan.id.desc()).all()
    
    timeline = []
    for scan in scans:
        timeline.append({
            "scan_id": scan.id,
            "timestamp": scan.timestamp,
            "subdomains": db.query(Subdomain).filter(Subdomain.scan_id == scan.id).count(),
            "vulns": {
                "critical": db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id, Vulnerability.severity == "critical").count(),
                "high": db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id, Vulnerability.severity == "high").count(),
                "medium": db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id, Vulnerability.severity == "medium").count(),
            }
        })
    
    return {"target": target, "total_scans": len(timeline), "timeline": timeline}

@app.get("/assets/{target_id}")
def get_assets(target_id: int, db: Session = Depends(get_db_session)):
    """Retorna todos los subdominios de un target."""
    # Buscar el último scan exitoso
    latest_scan = db.query(Scan).filter(Scan.target_id == target_id).order_by(Scan.id.desc()).first()
    if not latest_scan:
        return []
    
    assets = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all()
    return assets

@app.get("/finding/{finding_id}")
def get_finding_detail(finding_id: int, db: Session = Depends(get_db_session)):
    """Retorna el detalle completo de una vulnerabilidad."""
    v = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not v:
        return {"error": "Finding not found"}
    
    # Enriquecer con info de remediación (simulado basado en tipo)
    remediation = "Apply security patches and follow OWASP best practices."
    if "sql" in v.type.lower(): remediation = "Use parameterized queries and ORMs. Sanitize all user inputs."
    if "xss" in v.type.lower(): remediation = "Implement Content Security Policy (CSP) and encode output data."
    
    return {
        "id": v.id,
        "name": v.name,
        "type": v.type,
        "severity": v.severity,
        "url": v.url,
        "description": v.description or "No description provided.",
        "remediation": remediation,
        "vector": v.vector or "N/A",
        "cve": v.cve or "N/A",
        "timestamp": v.timestamp.isoformat() if v.timestamp else None
    }
