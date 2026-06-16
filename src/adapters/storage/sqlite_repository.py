from typing import List, Optional
from src.application.ports.asset_repository import IAssetRepository
from src.domain.models import Asset, Finding
from src.storage.database import SessionLocal
from src.storage.queries import DBQueries


class SQLiteAssetRepository(IAssetRepository):
    """Adapter for SQLite storage using DBQueries as single source of truth."""

    def __init__(self, session_factory=SessionLocal):
        self.session_factory = session_factory

    def save_asset(self, asset: Asset) -> None:
        with self.session_factory() as session:
            q = DBQueries(session)
            q.save_asset(asset)

    def find_asset_by_domain(self, domain: str) -> Optional[Asset]:
        with self.session_factory() as session:
            q = DBQueries(session)
            return q.find_asset_by_domain(domain)

    def save_finding(self, finding: Finding) -> None:
        with self.session_factory() as session:
            q = DBQueries(session)
            q.save_finding(finding)

    def get_findings_by_asset(self, asset_id: str) -> List[Finding]:
        with self.session_factory() as session:
            q = DBQueries(session)
            return q.get_findings_by_asset(asset_id)
