import importlib
import pkgutil
import logging
from pathlib import Path
from typing import Dict, List
from src.plugins.base import Plugin

logger = logging.getLogger("plugins")


class PluginLoader:

    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}

    def discover(self, paths: List[str] = None):
        paths = paths or ["plugins"]
        for path in paths:
            p = Path(path)
            if p.is_dir():
                self._load_from_directory(p)

    def _load_from_directory(self, path: Path):
        import sys
        sys.path.insert(0, str(path))
        for importer, modname, ispkg in pkgutil.iter_modules([str(path)]):
            try:
                module = importlib.import_module(modname)
                self._register_from_module(module)
            except Exception as e:
                logger.warning(f"Failed to load plugin {modname}: {e}")
        sys.path.pop(0)

    def _register_from_module(self, module):
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, Plugin) and attr is not Plugin:
                plugin = attr()
                manifest = plugin.get_manifest()
                self._plugins[manifest.name] = plugin
                logger.info(f"Loaded plugin: {manifest.name} v{manifest.version}")

    def get_plugin(self, name: str) -> Plugin:
        return self._plugins.get(name)

    def get_all(self) -> Dict[str, Plugin]:
        return self._plugins.copy()

    def get_plugins_for_hook(self, hook: str) -> List[Plugin]:
        return [p for p in self._plugins.values() if hook in p.get_manifest().hooks]


plugin_loader = PluginLoader()
