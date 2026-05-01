"""
Gestión de la Base de Datos (SQLite)
OzyRecon - Storage Layer
"""

from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Importar utilidades
from src.utils import log, save_json, load_json
from src.core.runtime_paths import get_runtime_root

# Importar modelos locales
from .models import Base, Target, Scan, Subdomain, Port, Vulnerability, Finding, AgentMemory, AgentLock, Session, WeightHistory, Hypothesis, Evidence, WorkflowStep

DB_PATH = get_runtime_root() / "db" / "ozyrecon.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
DB_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DB_URL, 
    connect_args={"check_same_thread": False, "timeout": 60}, # v7.7.1 - Increased timeout
    pool_size=20,       # v7.7.1 - Handle 20 concurrent scans
    max_overflow=40     # v7.7.1 - Burst capacity
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Inicializa las tablas si no existen y activa modo WAL."""
    from sqlalchemy import text
    Base.metadata.create_all(bind=engine)
    # Activar modo Write-Ahead Logging para concurrencia API
    try:
        with engine.connect() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL;"))
            conn.execute(text("PRAGMA synchronous=NORMAL;"))
            conn.commit()
    except Exception as e:
        log(f"Warning: Failed to set WAL mode: {e}", level="warn")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
