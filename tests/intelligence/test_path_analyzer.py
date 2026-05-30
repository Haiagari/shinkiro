from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from src.intelligence.path_analyzer import PathAnalyzer
from src.storage.database import Base
from src.storage.models import Scan, Subdomain, Target, Vulnerability


def test_path_analyzer_normalizes_lookup_target():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()

        scan = Scan(target_id=target.id, session_id="sid-1", mode="hunt", status="completed")
        session.add(scan)
        session.commit()

        session.add_all(
            [
                Subdomain(scan_id=scan.id, domain="api.example.com", ip="10.0.0.1"),
                Subdomain(scan_id=scan.id, domain="www.example.com", ip="10.0.0.1"),
                Vulnerability(
                    scan_id=scan.id, host="api.example.com", name="test", severity="high"
                ),
            ]
        )
        session.commit()

        analyzer = PathAnalyzer(session)
        paths = analyzer.analyze_target_paths("https://example.com./path")

        assert any(path["entry_point"] == "api.example.com" for path in paths)
    finally:
        session.close()
