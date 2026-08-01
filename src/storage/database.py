"""
Gestión de la Base de Datos (SQLite / PostgreSQL)
PromptWall - Storage Layer
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.utils import log
from src.core.runtime_paths import get_runtime_root

# Model imports register tables on Base.metadata (side-effect import).
from .models import (  # noqa: F401
    Base,
    Target,
    Scan,
    Subdomain,
    Port,
    Vulnerability,
    Finding,
    AgentMemory,
    AgentLock,
    Session,
    WeightHistory,
    Hypothesis,
    Evidence,
    WorkflowStep,
)

DEFAULT_DB_PATH = get_runtime_root() / "db" / "promptwall.db"
DB_PATH = DEFAULT_DB_PATH  # backward compat

DATABASE_URL = os.environ.get("OZY_DATABASE_URL", "")

if DATABASE_URL:
    DB_URL = DATABASE_URL
    connect_args = {}
    pool_size = 20
    max_overflow = 40
else:
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_URL = f"sqlite:///{DEFAULT_DB_PATH}"
    connect_args = {"check_same_thread": False, "timeout": 60}
    pool_size = 20
    max_overflow = 40

engine = create_engine(
    DB_URL,
    connect_args=connect_args,
    pool_size=pool_size,
    max_overflow=max_overflow,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    from sqlalchemy import text
    Base.metadata.create_all(bind=engine)
    if not DATABASE_URL:
        try:
            with engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL;"))
                conn.execute(text("PRAGMA synchronous=NORMAL;"))
                conn.commit()
        except Exception as e:
            log(f"Warning: Failed to set WAL mode: {e}", level="warn")
    else:
        log(f"Database: connected to {DB_URL}", level="info")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
