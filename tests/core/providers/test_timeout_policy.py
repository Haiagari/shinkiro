import subprocess

from src.core.context import ScanContext, set_context, clear_context
from src.core.providers.base import BaseProvider


class DummyProvider(BaseProvider):
    def __init__(self):
        super().__init__("dummy", "dummy-bin")

    def execute(self, target, **kwargs):
        return self._run_tool(["dummy", target], capability=kwargs.get("capability"), retries=0)


def test_run_tool_uses_context_timeout_policy(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.utils.subprocess.run", fake_run)
    ctx = ScanContext()
    ctx.timeout_policy = {"asset_discovery": 123, "default": 30}
    set_context(ctx)

    try:
        provider = DummyProvider()
        result = provider._run_tool(["dummy", "target"], capability="asset_discovery")
        assert result.stdout == "ok"
        assert captured["timeout"] == 123
    finally:
        clear_context()


def test_run_tool_falls_back_to_default_timeout(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.utils.subprocess.run", fake_run)
    set_context(ScanContext())

    try:
        provider = DummyProvider()
        provider._run_tool(["dummy", "target"], capability="asset_discovery")
        assert captured["timeout"] == 30
    finally:
        clear_context()
