from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from src.adapters.storage.sqlite_repository import SQLiteAssetRepository
from src.domain.models import Asset
from src.storage.database import Base
from src.storage.models import Target


def test_find_asset_by_domain_normalizes_lookup_target():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    setup_session = session_factory()
    try:
        setup_session.add(Target(domain="example.com"))
        setup_session.commit()

        repo = SQLiteAssetRepository(session_factory=session_factory)
        asset = repo.find_asset_by_domain("https://example.com./path")

        assert asset is not None
        assert asset.domain == "example.com"
    finally:
        setup_session.close()


def test_save_asset_normalizes_lookup_target_before_upsert():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    repo = SQLiteAssetRepository(session_factory=session_factory)

    repo.save_asset(Asset(domain="https://example.com./path", type="domain"))

    check_session = session_factory()
    try:
        stored = check_session.query(Target).first()
        assert stored is not None
        assert stored.domain == "example.com"
    finally:
        check_session.close()
