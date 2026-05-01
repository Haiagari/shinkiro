from pathlib import Path

from src.core.contracts import (
    CONTRACT_VERSION,
    MODE_ENVELOPE_FIELDS,
    SCAN_RESULT_FIELDS,
    SESSION_TRACE_FIELDS,
)


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_contract_field_sets_are_stable_and_unique():
    assert CONTRACT_VERSION == "ozy.runtime.v1"

    for fields in (MODE_ENVELOPE_FIELDS, SCAN_RESULT_FIELDS, SESSION_TRACE_FIELDS):
        assert fields
        assert len(fields) == len(set(fields))


def test_public_docs_reference_the_frozen_runtime_contract():
    readme = _read("README.md")
    runtime_contract = _read("docs/RUNTIME_CONTRACT.md")
    bridge_contract = _read("docs/BRIDGE_CONTRACT.md")
    usage = _read("docs/USAGE.md")
    install = _read("docs/INSTALL.md")

    assert "docs/RUNTIME_CONTRACT.md" in readme
    assert "docs/BRIDGE_CONTRACT.md" in readme
    assert "python ozy.py" in readme

    assert "src/core/contracts.py" in runtime_contract
    assert "GET /sessions/{session_id}/trace" in runtime_contract
    assert "frozen envelope fields" in runtime_contract.lower()

    assert "src/core/contracts.py" in bridge_contract
    assert "compatibility closure" in bridge_contract.lower()

    assert "session trace" in usage.lower()
    assert "session trace" in install.lower()
