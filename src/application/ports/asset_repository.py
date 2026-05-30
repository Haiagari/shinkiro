from abc import ABC, abstractmethod
from typing import List, Optional
from src.domain.models import Asset, Finding

class IAssetRepository(ABC):
    """Port for managing asset and finding persistence."""
    
    @abstractmethod
    def save_asset(self, asset: Asset) -> None:
        """Persists or updates an asset."""
        pass

    @abstractmethod
    def find_asset_by_domain(self, domain: str) -> Optional[Asset]:
        """Retrieves an asset by its domain name."""
        pass

    @abstractmethod
    def save_finding(self, finding: Finding) -> None:
        """Persists a new finding."""
        pass

    @abstractmethod
    def get_findings_by_asset(self, asset_id: str) -> List[Finding]:
        """Retrieves all findings associated with a specific asset."""
        pass
