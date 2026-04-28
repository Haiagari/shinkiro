from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from src.core.contracts import (
    MODE_ENVELOPE_FIELDS,
    SCAN_RESULT_FIELDS,
    SESSION_TRACE_FIELDS,
    missing_fields,
)
from src.core.api import get_session_trace
from src.export.schema import ScanResult
from src.modes.hunt import HuntMode
from src.storage.models import Base, Target, Scan


def test_scan_result_fields_are_frozen():
    result = ScanResult()
    payload = result.to_dict()

    assert result.contract_version == "scan-result.v1"
    assert missing_fields(payload, SCAN_RESULT_FIELDS) == []


def test_mode_envelope_fields_are_frozen():
    mode = HuntMode("contract.example.com")
    envelope = mode.build_output_envelope("completed")

    assert missing_fields(envelope, MODE_ENVELOPE_FIELDS) == []
    assert envelope["contract_version"] == "scan-result.v1"
    assert envelope["observability"]["session_id"] == mode.session_id

    mode.db_session.close()


def test_session_trace_fields_are_frozen():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    target = Target(domain="trace-contract.example.com")
    session.add(target)
    session.flush()
    session.add(Scan(
        target_id=target.id,
        session_id="trace-contract-session",
        mode="hunt",
        status="completed",
    ))
    session.commit()

    with patch("src.core.api.SessionLocal", return_value=session):
        trace = get_session_trace("trace-contract-session")

    assert missing_fields(trace, SESSION_TRACE_FIELDS) == []
    assert trace["session_id"] == "trace-contract-session"
    assert trace["summary"]["event_count"] >= 0

    session.close()
