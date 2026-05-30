from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.storage.database import Base
from src.storage.db_queries import get_latest_scan
from src.storage.models import Scan, Target
from src.storage.queries import DBQueries


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_db_queries_normalize_target_lookup():
    session = _make_session()
    try:
        session.add(Target(domain="example.com"))
        session.commit()

        query = DBQueries(session)
        target = query.get_target("https://example.com./path")

        assert target is not None
        assert target.domain == "example.com"
    finally:
        session.close()


def test_db_queries_get_latest_scan_normalizes_target_lookup():
    session = _make_session()
    try:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.add(Scan(target_id=target.id, session_id="sid-1", mode="hunt"))
        session.commit()

        latest = get_latest_scan(session, "https://example.com./path")

        assert latest is not None
        assert latest.session_id == "sid-1"
    finally:
        session.close()
