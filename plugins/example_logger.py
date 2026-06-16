from typing import Dict
from src.plugins.base import Plugin, PluginManifest
import logging

logger = logging.getLogger("plugin.example")


class ExampleLoggerPlugin(Plugin):
    def get_manifest(self) -> PluginManifest:
        return PluginManifest(
            name="example_logger",
            version="1.0.0",
            description="Logs all discovered assets for debugging",
            hooks=["asset_discovered", "scan_complete"]
        )

    def on_asset_discovered(self, asset: Dict) -> Dict:
        logger.info(f"[Plugin] Asset discovered: {asset.get('domain', 'unknown')}")
        return asset

    def on_scan_complete(self, scan_result: Dict) -> Dict:
        logger.info(f"[Plugin] Scan complete for {scan_result.get('target', 'unknown')}")
        return scan_result
