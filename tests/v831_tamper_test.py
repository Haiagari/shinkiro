from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.modes.forensic import ForensicMode
from src.storage.models import Base, Scan, Subdomain, Target
from src.utils.crypto import evidence_signer


def test_forensic_mode_detects_tampering(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionFactory = sessionmaker(bind=engine)
    session = SessionFactory()

    monkeypatch.setattr("src.storage.database.engine", engine)
    monkeypatch.setattr("src.storage.database.SessionLocal", SessionFactory)
    monkeypatch.setattr("src.modes.base.SessionLocal", SessionFactory)

    target = session.query(Target).filter_by(domain="tamper.test").first()
    if not target:
        target = Target(domain="tamper.test")
        session.add(target)
        session.commit()

    session_id = "forensic_tamper_test"
    scan = Scan(target_id=target.id, session_id=session_id, status="completed")
    session.add(scan)
    session.commit()

    data = {
        "domain": "hacker.tamper.test",
        "ip": "0.0.0.0",
        "http_status": 200,
        "title": "Owned",
        "semantic_labels": ["gate_admin"],
    }
    signature = evidence_signer.sign_data(data)

    sub = Subdomain(
        scan_id=scan.id,
        domain=data["domain"],
        ip=data["ip"],
        http_status=data["http_status"],
        title=data["title"],
        semantic_labels=data["semantic_labels"],
        evidence_signature=signature,
    )
    session.add(sub)
    session.commit()

    sub.ip = "8.8.8.8"
    session.commit()

    result = ForensicMode(session_id).execute()

    assert result["status"] == "completed"
    assert result["failed"] >= 1

    session.close()
