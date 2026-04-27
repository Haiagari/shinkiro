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

# Importar modelos locales
from .models import Base, Target, Scan, Subdomain, Port, Vulnerability, Finding, AgentMemory, AgentLock, Session, WeightHistory, Hypothesis, Evidence, WorkflowStep

DB_PATH = Path(__file__).resolve().parents[2] / "runtime" / "db" / "ozyrecon.db"
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
