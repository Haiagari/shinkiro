"""
Gestión de la Base de Datos (SQLite)
OzyRecon - Storage Layer
"""

from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Importar modelos locales
from .models import Base, Target, Scan, Subdomain, Port, Vulnerability, Finding, AgentMemory, AgentLock, Session, WeightHistory

DB_PATH = Path(__file__).resolve().parents[3] / "runtime" / "db" / "ozyrecon.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
DB_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Inicializa las tablas si no existen."""
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_scan_to_db(context: dict):
    """
    Persiste los hallazgos del context en la base de datos.
    Enhanced: guarda puertos, subdominios extendidos y vulnerabilidades con campos extra.
    """
    db = SessionLocal()
    try:
        target_domain = context.get("target")
        out_dir = context.get("out_dir")
        scan_status = context.get("scan_status", {})
        
        # 1. Asegurar que el Target existe
        target = db.query(Target).filter(Target.domain == target_domain).first()
        if not target:
            target = Target(domain=target_domain)
            db.add(target)
            db.commit()
            db.refresh(target)

        # 2. Crear o actualizar el Scan asociado a esta salida
        scan = None
        if out_dir:
            scan = db.query(Scan).filter(Scan.out_dir == out_dir).first()

        if not scan:
            scan = Scan(
                target_id=target.id,
                timestamp=context.get("start_time"),
                out_dir=out_dir,
                status=scan_status.get("status", "running"),
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
        else:
            scan.target_id = target.id
            scan.timestamp = context.get("start_time")
            scan.status = scan_status.get("status", scan.status or "running")
            db.add(scan)
            db.commit()
            db.refresh(scan)

        # Mantener el contexto sincronizado con la fila real del scan
        context.setdefault("scan_meta", {})
        context["scan_meta"]["scan_id"] = scan.id
        context["scan_meta"]["target_id"] = target.id

        # Limpiar datos previos del scan para evitar duplicados al persistir por fases
        db.query(Subdomain).filter(Subdomain.scan_id == scan.id).delete(synchronize_session=False)
        db.query(Port).filter(Port.scan_id == scan.id).delete(synchronize_session=False)
        db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).delete(synchronize_session=False)
        db.commit()

        # ════════════════════════════════════════════════════════════════════════════
        # 3. Guardar Subdominios (con campos extendidos)
        # ════════════════════════════════════════════════════════════════════════════
        recon = context.get("phases", {}).get("recon", {})
        all_subs = recon.get("all_subdomains", [])
        live_subs_data = recon.get("live_hosts_data", [])  # [{domain, http_status, title, ...}]
        
        # Mapeo rápido por dominio
        live_map = {d.get("domain"): d for d in live_subs_data}
        
        for s in all_subs:
            live_data = live_map.get(s, {})
            sub = Subdomain(
                scan_id=scan.id,
                domain=s,
                is_live=1 if s in live_map else 0,
                http_status=live_data.get("http_status"),
                title=live_data.get("title"),
                web_server=live_data.get("web_server"),
                content_length=live_data.get("content_length"),
                ip=live_data.get("ip")
            )
            db.add(sub)

        # ════════════════════════════════════════════════════════════════════════════
        # 4. Guardar Puertos (NEW)
        # ════════════════════════════════════════════════════════════════════════════
        ports_data = context.get("phases", {}).get("ports", {})
        open_ports = ports_data.get("open_ports", [])  # [{host, port, service, version, banner}]
        
        # Soporta formato legacy (lista de strings "host:port") y nuevo (lista de dicts)
        for p in open_ports:
            if isinstance(p, dict):
                port = Port(
                    scan_id=scan.id,
                    host=p.get("host", target_domain),
                    port=p.get("port"),
                    protocol=p.get("protocol", "tcp"),
                    service=p.get("service"),
                    version=p.get("version"),
                    state=p.get("state", "open"),
                    banner=p.get("banner")
                )
            else:
                # Formato legacy: "host:port" o "port"
                parts = str(p).split(":")
                port = Port(
                    scan_id=scan.id,
                    host=parts[0] if len(parts) > 1 else target_domain,
                    port=int(parts[-1]) if parts[-1].isdigit() else 80,
                    state="open"
                )
            db.add(port)

        # ════════════════════════════════════════════════════════════════════════════
        # 5. Guardar Vulnerabilidades (con campos extendidos)
        # ════════════════════════════════════════════════════════════════════════════
        vulns = context.get("phases", {}).get("vulns", {})
        for f in vulns.get("findings", []):
            v = Vulnerability(
                scan_id=scan.id,
                type=f.get("type"),
                severity=f.get("severity"),
                url=f.get("url") or f.get("raw"),
                description=f.get("description"),
                vector=f.get("vector"),
                cve=f.get("cve")
            )
            db.add(v)

        db.commit()

        # Guardar snapshot de estado del scan para consumo del dashboard
        if out_dir:
            status_path = Path(out_dir) / "status.json"
            status_history = scan_status.get("history", [])
            snapshot = {
                "target": target_domain,
                "scan_id": scan.id,
                "target_id": target.id,
                "out_dir": out_dir,
                "status": scan_status.get("status", scan.status or "running"),
                "phase": scan_status.get("phase", "unknown"),
                "progress": scan_status.get("progress", 0),
                "message": scan_status.get("message", ""),
                "error": scan_status.get("error"),
                "updated_at": datetime.utcnow().isoformat(),
                "history": status_history[-50:],
                "counts": {
                    "subdomains": len(recon.get("all_subdomains", [])),
                    "live_hosts": len(recon.get("live_hosts", [])),
                    "ports": len(ports_data.get("open_ports", [])),
                    "vulns": len(vulns.get("findings", [])),
                },
            }
            save_json(status_path, snapshot)

        return True
    except Exception as e:
        print(f"Error guardando en DB: {e}")
        db.rollback()
        return False
    finally:
        db.close()
