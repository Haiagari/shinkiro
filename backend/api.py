"""
API REST para el Framework de Bug Bounty
Uso: uvicorn backend.api:app --reload --port 8000
"""

from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import subprocess
import sys
from pathlib import Path
from typing import List

# Asegurar imports de `modules` cuando la API se carga como `backend.api`
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from modules.database import get_db, SessionLocal
from modules.models import Target, Scan, Vulnerability, Subdomain, Port, AgentMemory
from modules.db_queries import get_latest_scan, get_target_stats, get_scan_history
from modules.utils import load_json
import glob as glob_module

app = FastAPI(title="BugBounty Framework API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {
        "message": "BugBounty Framework API v1.0",
        "status": "online",
        "dashboard": "dashboard",
    }

@app.get("/scans")
def list_scans():
    """Lista todos los scans desde archivos JSON en runtime/scans/"""
    scans = []
    scans_dir = ROOT_DIR / "runtime" / "scans"
    if scans_dir.exists():
        for target_dir in sorted(scans_dir.iterdir()):
            if target_dir.is_dir():
                target_runs = sorted(target_dir.iterdir(), reverse=True)
                for run_dir in target_runs:
                    if run_dir.is_dir():
                        status_file = run_dir / "status.json"
                        if status_file.exists():
                            status = load_json(status_file)
                            scans.append({
                                "target": target_dir.name,
                                "run": run_dir.name,
                                "status": status.get("status", "unknown"),
                                "timestamp": status.get("timestamp", ""),
                            })
                            break
    return sorted(scans, key=lambda x: x.get("timestamp", ""), reverse=True)

@app.get("/scan/{target}/{run}")
def get_scan(target: str, run: str):
    """Obtiene los detalles de un scan específico desde archivos JSON"""
    scan_dir = ROOT_DIR / "runtime" / "scans" / target / run
    if not scan_dir.exists():
        return {"error": f"Scan no encontrado: {target}/{run}"}
    
    result = {"target": target, "run": run, "data": {}}
    
    # Cargar status.json
    status_file = scan_dir / "status.json"
    if status_file.exists():
        result["data"]["status"] = load_json(status_file)
    
    # Cargar otros archivos relevantes
    for subdir in ["recon", "ports", "crawler", "vulns", "fuzzer", "intelligence"]:
        subdir_path = scan_dir / subdir
        if subdir_path.exists():
            files = {}
            for f in sorted(subdir_path.iterdir()):
                if f.is_file() and f.suffix == ".json":
                    files[f.name] = load_json(f)
            if files:
                result["data"][subdir] = files
    
    return result

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
        main_path = Path(__file__).resolve().parent / "main.py"
        subprocess.run([sys.executable, str(main_path), "-t", target, "--full"])

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
            "reason": f"Vuln {v.severity}: {getattr(v, 'name', None) or v.type}"
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
        "name": getattr(v, "name", None) or v.type,
        "type": v.type,
        "severity": v.severity,
        "url": v.url,
        "description": v.description or "No description provided.",
        "remediation": remediation,
        "vector": v.vector or "N/A",
        "cve": v.cve or "N/A",
        "timestamp": v.timestamp.isoformat() if v.timestamp else None
    }


def _status_from_scan(scan: Scan | None) -> dict:
    if not scan or not scan.out_dir:
        return {}
    status_path = Path(scan.out_dir) / "status.json"
    if not status_path.exists():
        return {}
    return load_json(status_path)


def _scan_history_payload(scan: Scan, db: Session) -> dict:
    target_obj = db.query(Target).filter(Target.id == scan.target_id).first()
    status = _status_from_scan(scan)
    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
    ports = db.query(Port).filter(Port.scan_id == scan.id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()

    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "target": target_obj.domain if target_obj else "n/a",
        "status": status.get("status", scan.status or "completed"),
        "phase": status.get("phase", "unknown"),
        "progress": status.get("progress", 100 if scan.status == "completed" else 0),
        "message": status.get("message", ""),
        "error": status.get("error"),
        "updated_at": status.get("updated_at"),
        "started_at": scan.start_time.isoformat() if scan.start_time else None,
        "timestamp": scan.timestamp,
        "out_dir": scan.out_dir,
        "counts": {
            "subdomains": len(subdomains),
            "live_hosts": sum(1 for sub in subdomains if sub.is_live),
            "ports": len(ports),
            "vulns": len(vulns),
            "critical": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "critical"),
            "high": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "high"),
            "medium": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "medium"),
        },
        "events": status.get("history", [])[-4:],
    }


def _recent_scan_history(db: Session, target: str | None = None, limit: int = 8) -> list[dict]:
    if target:
        scans = get_scan_history(db, target, days=3650)[:limit]
    else:
        scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
    return [_scan_history_payload(scan, db) for scan in scans]


def _build_target_payload(target_obj: Target, db: Session) -> dict:
    latest_scan = get_latest_scan(db, target_obj.domain)
    status = _status_from_scan(latest_scan)
    subs = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all() if latest_scan else []
    ports = db.query(Scan).filter(Scan.id == latest_scan.id).first().ports if latest_scan else []
    vulns = latest_scan.vulnerabilities if latest_scan else []
    live_subs = [s for s in subs if s.is_live]

    return {
        "id": f"target-{target_obj.id}",
        "host": target_obj.domain,
        "mode": status.get("mode", "hunt"),
        "modeClass": "mode-hunt",
        "modeLabel": f"⚡ {status.get('mode', 'HUNT').upper()}",
        "modeName": status.get("mode", "HUNT").upper(),
        "findings": {
            "critical": sum(1 for v in vulns if (v.severity or "").lower() == "critical"),
            "high": sum(1 for v in vulns if (v.severity or "").lower() == "high"),
            "medium": sum(1 for v in vulns if (v.severity or "").lower() == "medium"),
        },
        "progress": status.get("progress", 100 if latest_scan and latest_scan.status == "completed" else 0),
        "lastScan": latest_scan.timestamp if latest_scan and latest_scan.timestamp else (latest_scan.start_time.strftime("%H:%M") if latest_scan and latest_scan.start_time else "n/a"),
        "ip": (live_subs[0].ip if live_subs and live_subs[0].ip else "n/a") if live_subs else "n/a",
        "hosting": "DB-backed scan",
        "techStack": (live_subs[0].web_server if live_subs and live_subs[0].web_server else "n/a") if live_subs else "n/a",
        "surface": f"{len(live_subs)} hosts · {len(ports)} puertos",
        "notes": [
            f"{event.get('phase', 'phase')}: {event.get('message', '')}"
            for event in status.get("history", [])[-2:]
        ] or [f"Scan {latest_scan.status}" if latest_scan else "Sin scans"],
    }


@app.get("/scan-status/{target}")
def scan_status(target: str, db: Session = Depends(get_db_session)):
    target_obj = db.query(Target).filter(Target.domain == target).first()
    if not target_obj:
        return {"error": "Target no encontrado"}

    latest_scan = get_latest_scan(db, target)
    if not latest_scan:
        return {"target": target, "status": "idle", "progress": 0, "phase": "none", "events": []}

    status = _status_from_scan(latest_scan)
    return {
        "target": target,
        "scan_id": latest_scan.id,
        "status": status.get("status", latest_scan.status or "completed"),
        "phase": status.get("phase", "unknown"),
        "progress": status.get("progress", 100 if latest_scan.status == "completed" else 0),
        "message": status.get("message", ""),
        "error": status.get("error"),
        "updated_at": status.get("updated_at"),
        "events": status.get("history", []),
        "counts": status.get("counts", {}),
    }


@app.get("/scan-history")
def scan_history(target: str | None = None, limit: int = 8, db: Session = Depends(get_db_session)):
    return {
        "target": target,
        "limit": limit,
        "items": _recent_scan_history(db, target=target, limit=limit),
    }


@app.get("/dashboard-state")
def dashboard_state(target: str | None = None, db: Session = Depends(get_db_session)):
    target_obj = None
    latest_scan = None
    recent_history = _recent_scan_history(db, target=None, limit=8)

    if target:
        target_obj = db.query(Target).filter(Target.domain == target).first()
        latest_scan = get_latest_scan(db, target) if target_obj else None

    if not target_obj:
        latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
        if latest_scan:
            target_obj = db.query(Target).filter(Target.id == latest_scan.target_id).first()

    if not target_obj:
        return {
            "project": {"name": "BugBounty Framework", "run": "live", "target": "n/a", "mode": "HUNT", "status": "idle"},
            "stats": {"subdomains": 0, "hosts": 0, "ports": 0, "steps": 0, "score": 0},
            "targets": [],
            "findings": [],
            "logs": [],
            "liveLogFeed": [],
            "memory": [],
            "modes": [],
            "chart": {"labels": [], "values": []},
            "scan_status": {"status": "idle", "phase": "none", "progress": 0, "events": []},
            "scan_history": recent_history,
        }

    stats = get_target_stats(db, target_obj.domain) if latest_scan else {"total_subdomains": 0, "live_subdomains": 0, "total_ports": 0, "critical_count": 0, "high_count": 0}
    status = _status_from_scan(latest_scan)

    findings_payload = []
    if latest_scan:
        for vuln in latest_scan.vulnerabilities:
            sev = (vuln.severity or "medium").lower()
            cvss_map = {"critical": 9.8, "high": 8.0, "medium": 5.3, "low": 2.1, "info": 0.0}
            findings_payload.append({
                "id": f"finding-{vuln.id}",
                "severity": sev,
                "badge": sev[:4].upper(),
                "severityLabel": sev.capitalize(),
                "title": getattr(vuln, "name", None) or vuln.type,
                "target": target_obj.domain,
                "location": vuln.url or "n/a",
                "cvss": cvss_map.get(sev, 5.0),
                "summary": vuln.description or "Sin descripción",
                "impact": vuln.description or "Pendiente de análisis",
                "evidence": [],
                "remediation": [],
                "tags": [vuln.type] if vuln.type else [],
            })

    memories = db.query(AgentMemory).filter(AgentMemory.target == target_obj.domain).order_by(AgentMemory.created_at.desc()).all()

    modes = [
        {"name": "HUNT", "icon": "⚡", "status": "ACTIVE" if status.get("status") == "running" else "DISPONIBLE", "running": True, "desc": "Scan agresivo en target"},
        {"name": "CONTINUO", "icon": "◎", "status": "DISPONIBLE", "running": False, "desc": "Monitor 24/7 con diff"},
        {"name": "CAMPAÑA", "icon": "▦", "status": "DISPONIBLE", "running": False, "desc": "Patrón en múltiples targets"},
        {"name": "INVESTIGACIÓN", "icon": "🔬", "status": "DISPONIBLE", "running": False, "desc": "CVE en superficie conocida"},
    ]

    scan_events = status.get("history", [])
    chart_values = [event.get("progress", 0) for event in scan_events] if scan_events else [0]
    chart_labels = [event.get("phase", str(i + 1)) for i, event in enumerate(scan_events)] if scan_events else ["0"]
    log_level_map = {
        "running": "agent",
        "completed": "ok",
        "error": "crit",
        "warn": "warn",
    }
    logs_payload = [
        {
            "time": event.get("time", "--:--"),
            "level": log_level_map.get(event.get("status", "running"), "info"),
            "label": event.get("phase", "PHASE").upper(),
            "message": event.get("message", ""),
        }
        for event in scan_events
    ]

    target_payload = _build_target_payload(target_obj, db)

    return {
        "project": {
            "name": "BugBounty Framework",
            "run": f"scan #{latest_scan.id if latest_scan else 'live'}",
            "target": target_obj.domain,
            "mode": status.get("mode", "HUNT"),
            "status": status.get("status", latest_scan.status if latest_scan else "idle"),
        },
        "stats": {
            "subdomains": stats.get("total_subdomains", 0),
            "hosts": stats.get("live_subdomains", 0),
            "ports": stats.get("total_ports", 0),
            "steps": len(scan_events) or 0,
            "score": min(1, ((stats.get("critical_count", 0) * 0.18) + (stats.get("high_count", 0) * 0.08) + 0.3)),
        },
        "targets": [target_payload],
        "findings": findings_payload,
        "logs": logs_payload[-14:],
        "liveLogFeed": logs_payload[-6:],
        "memory": [
            {
                "key": memory.key,
                "value": memory.value,
                "confidence": memory.confidence,
            }
            for memory in memories
        ],
        "modes": modes,
        "chart": {
            "labels": chart_labels,
            "values": chart_values,
        },
        "scan_status": {
            "target": target_obj.domain,
            "scan_id": latest_scan.id if latest_scan else None,
            "status": status.get("status", latest_scan.status if latest_scan else "idle"),
            "phase": status.get("phase", "unknown"),
            "progress": status.get("progress", 0),
            "message": status.get("message", ""),
            "error": status.get("error"),
            "updated_at": status.get("updated_at"),
            "events": scan_events,
        },
        "scan_history": recent_history,
    }
