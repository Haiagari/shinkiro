import subprocess

import pytest

from src.utils import run_cmd


def test_run_cmd_retries_once_on_timeout(monkeypatch):
    calls = []
    sleeps = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs.get("timeout"))
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=kwargs.get("args") or args[0], timeout=kwargs.get("timeout"))
        return subprocess.CompletedProcess(args[0], 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.utils.subprocess.run", fake_run)
    monkeypatch.setattr("src.utils.time.sleep", lambda seconds: sleeps.append(seconds))

    result = run_cmd(["echo", "hi"], timeout=1, retries=1, backoff=2.0)

    assert result.stdout == "ok"
    assert len(calls) == 2
    assert sleeps == [1.0]


def test_run_cmd_exhausts_retries(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=kwargs.get("args") or args[0], timeout=kwargs.get("timeout"))

    monkeypatch.setattr("src.utils.subprocess.run", fake_run)
    monkeypatch.setattr("src.utils.time.sleep", lambda seconds: None)

    with pytest.raises(subprocess.TimeoutExpired):
        run_cmd(["echo", "hi"], timeout=1, retries=1)
