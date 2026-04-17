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
    Retorna timeline de evolución de un target.
    Muestra cambios entre scans a lo largo del tiempo.
    """
    import json
    from datetime import datetime
    
    target_obj = db.query(Target).filter(Target.domain == target).first()
    if not target_obj:
        return {"error": "Target no encontrado"}
    
    # Buscar todos los scans de este target
    scans = db.query(Scan).filter(Scan.target_id == target_obj.id).order_by(Scan.start_time.desc()).all()
    
    timeline = []
    for scan in scans:
        # Cargar datos del scan desde el output directo
        output_dir = Path("output") / target
        if not output_dir.exists():
            continue
        
        # Buscar directorio de este scan específico
        scan_dirs = sorted(output_dir.glob("*"), key=lambda x: x.name, reverse=True)
        
        scan_data = {
            "scan_id": scan.id,
            "timestamp": scan.start_time.isoformat() if scan.start_time else None,
            "subdomains": 0,
            "hosts": 0,
            "urls": 0,
            "vulns": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "changes": {},
        }
        
        # Leer datos directamente de archivos
        for sd in scan_dirs[:1]:  # Solo el más reciente
            recon_dir = sd / "recon"
            ports_dir = sd / "ports"
            urls_dir = sd / "urls"
            vulns_dir = sd / "vulns"
            
            if recon_dir.exists():
                subs = recon_dir / "all_subdomains.txt"
                if subs.exists():
                    scan_data["subdomains"] = len(subs.read_text().splitlines())
                hosts = recon_dir / "live_hosts.txt"
                if hosts.exists():
                    scan_data["hosts"] = len(hosts.read_text().splitlines())
            
            if urls_dir.exists():
                urls = urls_dir / "all_urls.txt"
                if urls.exists():
                    scan_data["urls"] = len(urls.read_text().splitlines())
            
            if vulns_dir.exists():
                # Leer findings
                vuln_file = vulns_dir / "results.json"
                if vuln_file.exists():
                    data = json.loads(vuln_file.read_text())
                    findings = data.get("findings", [])
                    
                    for sev in ["critical", "high", "medium", "low"]:
                        scan_data["vulns"][sev] = len([f for f in findings if f.get("severity", "").lower() == sev])
        
        timeline.append(scan_data)
    
    # Calcular cambios entre scans
    changes = []
    for i in range(1, len(timeline)):
        prev = timeline[i-1]
        curr = timeline[i]
        
        sub_change = curr["subdomains"] - prev.get("subdomains", 0)
        vuln_change = sum(curr["vulns"].values()) - sum(prev.get("vulns", {}).values())
        
        if sub_change != 0 or vuln_change != 0:
            changes.append({
                "from": prev["timestamp"],
                "to": curr["timestamp"],
                "subdomains_diff": sub_change,
                "vulns_diff": vuln_change,
            })
    
    return {
        "target": target,
        "total_scans": len(timeline),
        "timeline": timeline,
        "changes": changes,
        "current": timeline[0] if timeline else {},
    }

@app.get("/pocs")
def get_pocs(db: Session = Depends(get_db_session)):
    """
    Retorna PoCs generados para las vulnerabilidades críticas.
    """
    from modules.ai_analyzer import generate_poc_for_finding
    
    vulns = db.query(Vulnerability).filter(
        Vulnerability.severity.in_(["critical", "high"])
    ).limit(10).all()
    
    pocs = []
    for v in vulns:
        poc_data = generate_poc_for_finding({
            "type": v.name or v.vuln_type,
            "url": v.url,
            "name": v.name,
        })
        pocs.append({
            "finding": v.name,
            "url": v.url,
            "type": poc_data.get("title", v.vuln_type),
            "poc": poc_data.get("poc", ""),
            "impact": poc_data.get("impact", ""),
        })
    
    return pocs
