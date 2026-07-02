"""
PromptWall Storage Module
Maneja persistencia SQLite, modelos y consultas.
"""

from .database import init_db, get_db, DB_PATH, engine, SessionLocal
from .models import (
    Base,
    Target,
    Scan,
    Subdomain,
    Port,
    Vulnerability,
    Session,
    Finding,
    AgentMemory,
    AgentLock,
)
from .queries import DBQueries
from .diff import DiffEngine

__all__ = [
    # Database
    'init_db',
    'get_db',
    'DB_PATH',
    'engine',
    'SessionLocal',
    # Models
    'Base',
    'Target',
    'Scan',
    'Subdomain',
    'Port',
    'Vulnerability',
    'Session',
    'Finding',
    'AgentMemory',
    'AgentLock',
    # Queries
    'DBQueries',
    # Diff
    'DiffEngine',
]