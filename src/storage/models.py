"""
Modelos de Datos para la Base de Datos (SQLAlchemy)
OzyRecon Storage Layer - Modelos optimizados.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Index, JSON
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

# ══════════════════════════════════════════════════════════════════════════════
# ÍNDICES PARA OPTIMIZACIÓN DE QUERIES
# ══════════════════════════════════════════════════════════════════════════════

idx_target_domain = Index('idx_target_domain', 'targets', 'domain')
idx_subdomain_scan_domain = Index('idx_subdomain_scan_domain', 'subdomains', 'scan_id', 'domain')
idx_vuln_scan_severity = Index('idx_vuln_scan_severity', 'vulnerabilities', 'scan_id', 'severity')
idx_port_scan_host = Index('idx_port_scan_host', 'ports', 'scan_id', 'host', 'port')


# ══════════════════════════════════════════════════════════════════════════════
# MODELOS DE MEMORIA DEL AGENTE
# ══════════════════════════════════════════════════════════════════════════════

class AgentMemory(Base):
    """Memoria del agente - almacena razonamientos entre sesiones."""
    __tablename__ = "agent_memory"
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), index=True)
    mode = Column(String(50))  # hunt, continuo, campaign, etc.
    key = Column(String(100))  # tech_stack, attack_surface, priority_reason
    value = Column(JSON)  # el razonamiento estructurado
    confidence = Column(Float, default=1.0)  # 0.0 a 1.0
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class AgentLock(Base):
    """Lock para evitar ejecuciones concurrentes del agente."""
    __tablename__ = "agent_locks"
    mode = Column(String(50), primary_key=True)
    locked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)


# ══════════════════════════════════════════════════════════════════════════════
# MODELOS PRINCIPALES
# ══════════════════════════════════════════════════════════════════════════════

class Target(Base):
    """Target/Objetivo a escanear."""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    last_scan = Column(DateTime, nullable=True)
    
    # Metadata
    in_scope = Column(Integer, default=1)
    priority = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # Lista de tags
    
    # Tech stack detectado
    technologies = Column(JSON, nullable=True)
    
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """Una ejecución de escaneo."""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    session_id = Column(String(100), unique=True, index=True)
    timestamp = Column(String(50))
    
    # Estado
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    mode = Column(String(50))  # hunt, continuous, campaign, research, forensic, servicio
    
    # Tiempos
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    # Resultados
    subdomains_found = Column(Integer, default=0)
    hosts_alive = Column(Integer, default=0)
    ports_found = Column(Integer, default=0)
    findings = Column(Integer, default=0)
    
    # Output
    out_dir = Column(String(500), nullable=True)
    errors = Column(Text, nullable=True)
    
    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Subdomain(Base):
    """Subdominio encontrado."""
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    domain = Column(String(255), nullable=False, index=True)
    
    # Estado
    is_live = Column(Integer, default=0)  # 0=dead, 1=live
    ip = Column(String(50))
    
    # HTTP Info
    http_status = Column(Integer)
    title = Column(String(500))
    web_server = Column(String(200))
    technologies = Column(JSON, nullable=True)
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="subdomains")


class Port(Base):
    """Puerto abierto detectado."""
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    host = Column(String(255), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    
    # Servicio
    service = Column(String(100))
    state = Column(String(20), default="open")
    version = Column(String(200))
    product = Column(String(100))
    
    # Extra
    extra_info = Column(String(500))
    
    scan = relationship("Scan", back_populates="ports")


class Vulnerability(Base):
    """Vulnerabilidad encontrada."""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    
    # Identificación
    name = Column(String(255), nullable=False)
    type = Column(String(100))  # xss, sqli, lfi, etc.
    
    # Severidad
    severity = Column(String(20))  # critical, high, medium, low, info
    cvss = Column(Float, nullable=True)
    
    # Ubicación
    host = Column(String(255))
    path = Column(String(500))
    param = Column(String(200))
    
    # Detalle
    description = Column(Text)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    
    # Estado
    status = Column(String(20), default="open")  # open, confirmed, false_positive, fixed
    reported = Column(Integer, default=0)
    
    scan = relationship("Scan", back_populates="vulnerabilities")


# ══════════════════════════════════════════════════════════════════════════════
# MODELOS DE SESIÓN (para tracking de ejecuciones)
# ══════════════════════════════════════════════════════════════════════════════

class Session(Base):
    """Sesión de ejecución - historial completo."""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(100), unique=True, nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)
    mode = Column(String(50))
    
    # Tiempos
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)  # segundos
    
    # Estado final
    status = Column(String(20))  # success, failed, interrupted
    exit_code = Column(Integer)
    
    # Resultados
    subdomains = Column(Integer, default=0)
    hosts = Column(Integer, default=0)
    ports = Column(Integer, default=0)
    findings = Column(Integer, default=0)
    
    # Errores
    error_summary = Column(Text, nullable=True)
    
    # Config usada
    config_used = Column(JSON, nullable=True)


class Finding(Base):
    """Hallazgo individual - para deduplicación."""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False, index=True)
    session_id = Column(String(100), index=True)
    
    # Identificación
    name = Column(String(255), nullable=False)
    type = Column(String(100))
    
    # Severidad
    severity = Column(String(20))
    cvss = Column(Float)
    
    # Location
    host = Column(String(255))
    url = Column(String(1000))
    path = Column(String(500))
    param = Column(String(200))
    
    # Content
    description = Column(Text)
    evidence = Column(Text, nullable=True)
    
    # Estado
    status = Column(String(20), default="new")  # new, confirmed, false_positive, duplicate, resolved
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    seen_count = Column(Integer, default=1)
    
    # Relaciones
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=True)

class WeightHistory(Base):
    """Historial de pesos de scoring para visualización."""
    __tablename__ = 'weight_history'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    reputation = Column(Float)
    novelty = Column(Float)
    diff = Column(Float)
    decision_id = Column(String(100), nullable=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODELOS OZYRECON v5.0 (Validation & Evidence)
# ══════════════════════════════════════════════════════════════════════════════

class Hypothesis(Base):
    """Hipótesis de ataque generada por el motor de inteligencia."""
    __tablename__ = 'hypotheses'
    
    id = Column(String(100), primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    scan_id = Column(Integer, ForeignKey('scans.id'))
    
    type = Column(String(50))  # idor, sqli, exposed_api, etc.
    description = Column(Text)
    url = Column(String(1000), nullable=True)
    severity = Column(String(20))
    confidence = Column(Float, default=0.0)
    
    # Human Gate
    status = Column(String(50), default="pending_approval") # pending_approval, approved, rejected, validation_in_progress, validated, failed_validation
    approved_at = Column(DateTime, nullable=True)
    risk_level = Column(String(20), default="medium")
    
    # Data
    signals = Column(JSON, nullable=True) # Lista de señales que originaron la hipótesis
    validation_method = Column(Text, nullable=True) # Descripción de cómo validarla
    
    evidences = relationship("Evidence", back_populates="hypothesis", cascade="all, delete-orphan")
    workflow_steps = relationship("WorkflowStep", back_populates="hypothesis", cascade="all, delete-orphan")

class Evidence(Base):
    """Evidencia recolectada durante la validación."""
    __tablename__ = 'evidence'
    
    id = Column(String(100), primary_key=True)
    hypothesis_id = Column(String(100), ForeignKey('hypotheses.id'))
    
    type = Column(String(50)) # http_response, screenshot, console_output, hash
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    data = Column(Text) # Contenido o path a archivo
    metadata_json = Column(JSON, nullable=True)
    hash_sha256 = Column(String(64), nullable=True)
    
    hypothesis = relationship("Hypothesis", back_populates="evidences")

class WorkflowStep(Base):
    """Tracking de estados para una hipótesis o target."""
    __tablename__ = 'workflow_history'
    
    id = Column(Integer, primary_key=True)
    hypothesis_id = Column(String(100), ForeignKey('hypotheses.id'), nullable=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=True)
    
    state = Column(String(50)) # DISCOVERED, ENUMERATED, ANALYZED, HYPOTHESIZED, ...
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(50)) # system, user, ai
    notes = Column(Text, nullable=True)
    
    hypothesis = relationship("Hypothesis", back_populates="workflow_steps")
