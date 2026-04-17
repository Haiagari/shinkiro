"""
Modelos de Datos para la Base de Datos (SQLAlchemy)
Enhanced with Port table, extended fields, and indexes.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Index
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
# MODELOS PRINCIPALES
# ══════════════════════════════════════════════════════════════════════════════

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="target")


class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    timestamp = Column(String(50))
    status = Column(String(50), default="completed")
    out_dir = Column(String(500))
    start_time = Column(DateTime, default=datetime.utcnow)
    
    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = 'subdomains'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    domain = Column(String(255), nullable=False)
    is_live = Column(Integer, default=0)  # 0 = dead, 1 = live
    ip = Column(String(50))
    # Extended fields
    http_status = Column(Integer)
    title = Column(String(500))
    web_server = Column(String(200))
    content_length = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="subdomains")


class Port(Base):
    __tablename__ = 'ports'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    host = Column(String(100), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service = Column(String(100))
    version = Column(String(100))
    state = Column(String(20), default="open")
    banner = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="ports")


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)  # critical, high, medium, low, info
    url = Column(Text)
    description = Column(Text)
    # Extended fields
    vector = Column(String(100))  # e.g., CVSS vector string
    cve = Column(String(50))  # CVE-YYYY-NNNNN
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="vulnerabilities")
