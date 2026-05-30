import subprocess

from src.core.providers.base import BaseProvider


class DummyProvider(BaseProvider):
    def __init__(self):
        super().__init__("dummy", "dummy-bin")

    def execute(self, target, **kwargs):
        return self._run_tool(["dummy", target], timeout=kwargs.get("timeout", 30), retries=kwargs.get("retries", 0))


def test_base_provider_run_tool_uses_retry(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])
        return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

    monkeypatch.setattr("src.utils.subprocess.run", fake_run)
    monkeypatch.setattr("src.utils.time.sleep", lambda seconds: None)
    provider = DummyProvider()

    result = provider._run_tool(["dummy", "target"], timeout=2, retries=1)

    assert result.stdout == "done"
    assert len(calls) == 2
