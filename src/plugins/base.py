from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List


@dataclass
class PluginManifest:
    name: str
    version: str
    description: str
    hooks: List[str] = field(default_factory=list)


class Plugin(ABC):

    @abstractmethod
    def get_manifest(self) -> PluginManifest:
        ...

    def on_asset_discovered(self, asset: Dict) -> Dict:
        return asset

    def on_finding_detected(self, finding: Dict) -> Dict:
        return finding

    def on_scan_complete(self, scan_result: Dict) -> Dict:
        return scan_result

    def on_export(self, export_data: Dict) -> Dict:
        return export_data
