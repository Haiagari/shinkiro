from typing import List, Optional
from sqlalchemy.orm import Session
from src.application.ports.asset_repository import IAssetRepository
from src.domain.models import Asset, Finding, Service
from src.storage.models import Target, Finding as FindingModel, Port
from src.core.target_normalizer import normalize_lookup_target
from src.storage.database import SessionLocal

class SQLiteAssetRepository(IAssetRepository):
    """Adapter for SQLite storage using SQLAlchemy."""
    
    def __init__(self, session_factory=SessionLocal):
        self.session_factory = session_factory

    def save_asset(self, asset: Asset) -> None:
        """Persists or updates an asset mapping to Target and Subdomain/Ports models."""
        with self.session_factory() as session:
            # Check if target exists by domain
            lookup_domain = normalize_lookup_target(asset.domain)
            target = session.query(Target).filter(Target.domain == lookup_domain).first()
            if not target:
                target = Target(domain=lookup_domain)
                session.add(target)
            
            target.tags = asset.tags
            target.notes = asset.metadata.get("notes")
            
            # Map services to Ports
            # In OzyRecon legacy, Ports are linked to a Scan, but Asset is Domain level.
            # For now, we update Target metadata if needed, or we could handle Subdomain model.
            # To stay faithful to the port interface:
            session.commit()

    def find_asset_by_domain(self, domain: str) -> Optional[Asset]:
        """Retrieves an asset by its domain name."""
        with self.session_factory() as session:
            lookup_domain = normalize_lookup_target(domain)
            target = session.query(Target).filter(Target.domain == lookup_domain).first()
            if not target:
                return None
            
            # Note: Legacy Target doesn't store IP directly (it's in Subdomain), 
            # but for the domain model we simplify.
            return Asset(
                domain=target.domain,
                type="domain",
                tags=target.tags or [],
                metadata={"notes": target.notes} if target.notes else {}
            )

    def save_finding(self, finding: Finding) -> None:
        """Persists a new finding."""
        with self.session_factory() as session:
            db_finding = FindingModel(
                target=finding.asset_id,
                name=finding.title,
                severity=finding.severity,
                description=finding.description,
                path=finding.path,
                param=finding.param
            )
            session.add(db_finding)
            session.commit()

    def get_findings_by_asset(self, asset_id: str) -> List[Finding]:
        """Retrieves all findings associated with a specific asset."""
        with self.session_factory() as session:
            db_findings = session.query(FindingModel).filter(FindingModel.target == asset_id).all()
            return [
                Finding(
                    title=f.name,
                    severity=f.severity,
                    description=f.description,
                    asset_id=f.target,
                    path=f.path,
                    param=f.param
                ) for f in db_findings
            ]
