from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fastapi import HTTPException
from src.core.api import get_autonomy_plan
from src.storage.models import Base, Target, Scan, Subdomain, Port


def test_intelligence_autonomy_endpoint_returns_safe_plan():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    target = Target(domain="api-phase4.example.com")
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        session_id="session-api-phase4",
        mode="hunt",
        status="completed",
    )
    session.add(scan)
    session.flush()

    session.add_all([
        Subdomain(scan_id=scan.id, domain="api.api-phase4.example.com", is_live=1),
        Port(scan_id=scan.id, host="api.api-phase4.example.com", port=8080, service="http", state="open"),
    ])
    session.commit()

    with patch("src.core.api.SessionLocal", return_value=session):
        data = get_autonomy_plan("api-phase4.example.com")

    assert data["phase"] == "phase4-safe"
    assert data["priority_targets"]
    assert data["analysis_prompts"]
    assert data["work_units"]

    session.close()


def test_intelligence_autonomy_endpoint_raises_for_missing_target():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    with patch("src.core.api.SessionLocal", return_value=session):
        try:
            get_autonomy_plan("missing.example.com")
        except HTTPException as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError("Expected HTTPException for missing target")

    session.close()
