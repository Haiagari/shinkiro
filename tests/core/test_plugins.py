import pytest
from src.core.tool_manager import ToolManager, tool_manager

def test_plugin_registration_capability():
    """
    Test that we can register new capabilities and providers at runtime.
    """
    class MockPlugin:
        def __init__(self):
            self.name = "mock_plugin"
        def is_available(self): return True
        def execute(self, target, **kwargs): return ["plugin_result"]
        
    plugin = MockPlugin()
    tool_manager.register_provider("custom_capability", plugin)
    
    results = tool_manager.run_capability("custom_capability", "test.com", all_providers=True)
    assert "plugin_result" in results


def test_tool_manager_hook_registry_emits_events():
    manager = ToolManager()
    events = []

    def hook(event_name, **payload):
        events.append((event_name, payload.get("capability")))

    manager.register_hook("before_capability", hook)
    manager.register_hook("after_capability", hook)

    class MockPlugin:
        def __init__(self):
            self.name = "hook_plugin"

        def is_available(self):
            return True

        def execute(self, target, **kwargs):
            return ["hook_result"]

    manager.register_provider("hook_capability", MockPlugin())
    manager.run_capability("hook_capability", "test.com", all_providers=True)

    assert ("before_capability", "hook_capability") in events
    assert ("after_capability", "hook_capability") in events
