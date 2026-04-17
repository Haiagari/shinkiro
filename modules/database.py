"""
Gestión de la Base de Datos (SQLite)
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, Target, Scan, Subdomain, Vulnerability

DB_URL = "sqlite:///bugbounty.db"

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
    """
    db = SessionLocal()
    try:
        target_domain = context.get("target")
        
        # 1. Asegurar que el Target existe
        target = db.query(Target).filter(Target.domain == target_domain).first()
        if not target:
            target = Target(domain=target_domain)
            db.add(target)
            db.commit()
            db.refresh(target)

        # 2. Crear el Scan
        scan = Scan(
            target_id=target.id,
            timestamp=context.get("start_time"),
            out_dir=context.get("out_dir")
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # 3. Guardar Subdominios
        recon = context.get("phases", {}).get("recon", {})
        all_subs = recon.get("all_subdomains", [])
        live_subs = set(recon.get("live_hosts", [])) # Simplificado
        
        for s in all_subs:
            sub = Subdomain(
                scan_id=scan.id,
                domain=s,
                is_live=1 if any(s in l for l in live_subs) else 0
            )
            db.add(sub)

        # 4. Guardar Vulnerabilidades
        vulns = context.get("phases", {}).get("vulns", {})
        for f in vulns.get("findings", []):
            v = Vulnerability(
                scan_id=scan.id,
                type=f.get("type"),
                severity=f.get("severity"),
                url=f.get("url") or f.get("raw")
            )
            db.add(v)

        db.commit()
        return True
    except Exception as e:
        print(f"Error guardando en DB: {e}")
        db.rollback()
        return False
    finally:
        db.close()
