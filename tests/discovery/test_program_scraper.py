import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.storage.models import Base, Target
from src.discovery.targets import program_scraper


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_save_scope_to_db_inserts_targets(db_session):
    scope_data = {
        "platform": "hackerone",
        "program": "acme",
        "scope": [
            {"type": "DOMAIN", "value": "Example.COM", "eligible_for_bounty": True},
            {"type": "WILDCARD", "value": "*.example.org", "eligible_for_bounty": False},
        ],
    }

    original_session_local = program_scraper.SessionLocal
    program_scraper.SessionLocal = lambda: db_session
    try:
        saved = program_scraper.save_scope_to_db(scope_data)
    finally:
        program_scraper.SessionLocal = original_session_local

    assert saved == 2
    target = db_session.query(Target).filter_by(domain="example.com").first()
    assert target is not None
    assert target.in_scope == 1
    assert "hackerone:acme" in (target.notes or "")
    assert "bounty" in (target.tags or [])

    wildcard = db_session.query(Target).filter_by(domain="*.example.org").first()
    assert wildcard is not None
    assert "Eligible for bounty=False" in (wildcard.notes or "")

