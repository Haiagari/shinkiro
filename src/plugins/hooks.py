import logging
from typing import Dict
from src.plugins.loader import plugin_loader

logger = logging.getLogger("plugins.hooks")


def dispatch_hook(hook: str, data: Dict) -> Dict:
    result = data
    for plugin in plugin_loader.get_plugins_for_hook(hook):
        try:
            hook_method = getattr(plugin, f"on_{hook}", None)
            if hook_method:
                result = hook_method(result) or result
        except Exception as e:
            logger.warning(
                f"Plugin '{plugin.get_manifest().name}' failed on hook '{hook}': {e}"
            )
    return result
