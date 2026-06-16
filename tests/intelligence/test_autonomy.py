import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.storage.models import Base, Target, Scan, Subdomain, Port, Vulnerability
from src.intelligence.autonomy.autonomy import AutonomyPlanner


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def populated_session(db_session):
    target = Target(domain="phase4.example.com")
    db_session.add(target)
    db_session.flush()

    scan = Scan(
        target_id=target.id,
        session_id="session-phase4",
        mode="hunt",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()

    db_session.add_all([
        Subdomain(scan_id=scan.id, domain="app.phase4.example.com", is_live=1),
        Subdomain(scan_id=scan.id, domain="admin.phase4.example.com", is_live=0),
        Port(scan_id=scan.id, host="app.phase4.example.com", port=8080, service="http", state="open"),
        Port(scan_id=scan.id, host="app.phase4.example.com", port=5432, service="postgres", state="open"),
        Vulnerability(scan_id=scan.id, name="Exposed panel", type="exposed_panel", severity="high", host="admin.phase4.example.com", path="http://admin.phase4.example.com"),
    ])
    db_session.commit()
    return db_session


def test_autonomy_planner_builds_safe_plan(populated_session):
    planner = AutonomyPlanner(populated_session)
    plan = planner.build_plan("phase4.example.com")

    assert plan.phase == "phase4-safe"
    assert plan.target == "phase4.example.com"
    assert plan.priority_targets
    assert any(rec["priority"] == "HIGH" for rec in plan.recommendations)
    assert plan.analysis_prompts
    assert plan.lab_decoys
    assert "safe phase 4 autonomy" in plan.summary.lower()


def test_autonomy_planner_requires_known_target(db_session):
    planner = AutonomyPlanner(db_session)

    with pytest.raises(ValueError):
        planner.build_plan("missing.example.com")
