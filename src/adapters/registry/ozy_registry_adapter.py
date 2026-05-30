import json
import os
from typing import Any, Dict
from src.application.ports.registry_client import IRegistryClient

class OzyRegistryAdapter(IRegistryClient):
    """
    Local-First Registry Adapter.
    Looks for a registry.json file locally but follows the Ozy Ecosystem logic.
    """

    def __init__(self, registry_path: str = "config/registry.json"):
        self.registry_path = registry_path
        self._registry_cache = {}
        self._load_registry()

    def _load_registry(self):
        if os.path.exists(self.registry_path):
            try:
                with open(self.registry_path, 'r') as f:
                    self._registry_cache = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._registry_cache = {}
        else:
            # Default minimal registry if file doesn't exist
            self._registry_cache = {
                "sources": {
                    "nmap": {"approved": True, "version": "7.92", "capabilities": ["port-scan", "version-detection"]},
                    "subfinder": {"approved": True, "version": "2.5.5", "capabilities": ["subdomain-discovery"]}
                }
            }

    def get_source_metadata(self, source_id: str) -> Dict[str, Any]:
        sources = self._registry_cache.get("sources", {})
        return sources.get(source_id, {})

    def is_source_approved(self, source_id: str) -> bool:
        metadata = self.get_source_metadata(source_id)
        return metadata.get("approved", False)
