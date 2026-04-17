"""
Modelos de Datos para la Base de Datos (SQLAlchemy)
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False)
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
    subdomains = relationship("Subdomain", back_populates="scan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Subdomain(Base):
    __tablename__ = 'subdomains'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    domain = Column(String(255))
    is_live = Column(Integer, default=0) # 0 o 1
    ip = Column(String(50))
    
    scan = relationship("Scan", back_populates="subdomains")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    type = Column(String(100))
    severity = Column(String(50))
    url = Column(Text)
    description = Column(Text)
    
    scan = relationship("Scan", back_populates="vulnerabilities")
