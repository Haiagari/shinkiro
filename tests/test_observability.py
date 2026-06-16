from src.core.context import ScanContext
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from src.core.api import get_session_trace
from src.intelligence.learning.decision_log import Decision, DecisionRepository
from src.storage.models import Base, Target, Scan, Session as ScanSession, Hypothesis, Evidence, WorkflowStep


def test_scan_context_observability_record_includes_derived_fields():
    ctx = ScanContext(session_id="sess-obs", target="obs.example.com", mode="hunt")
    ctx.mark_running()
    ctx.add_result("discovery", {"status": "done"})
    ctx.add_error("timeout on port 443")
    ctx.mark_completed()

    record = ctx.to_observability_record()

    assert record["session_id"] == "sess-obs"
    assert record["target"] == "obs.example.com"
    assert record["error_count"] == 1
    assert record["result_keys"] == ["discovery"]
    assert record["is_terminal"] is True
    assert record["status"] == "completed"
    assert record["event_count"] >= 4
    assert record["last_event"]["stage"] == "status"


def test_session_trace_endpoint_returns_consolidated_observability():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    target = Target(domain="trace.example.com")
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        session_id="session-trace",
        mode="hunt",
        status="completed",
        subdomains_found=1,
        hosts_alive=1,
        ports_found=1,
        findings=1,
    )
    session.add(scan)
    session.flush()

    session.add(ScanSession(
        session_id="session-trace",
        target="trace.example.com",
        mode="hunt",
        status="success",
        subdomains=1,
        hosts=1,
        ports=1,
        findings=1,
    ))

    hypo = Hypothesis(
        id="hyp-trace",
        target_id=target.id,
        scan_id=scan.id,
        type="EXPOSED_PANEL",
        description="Admin panel",
        url="https://trace.example.com/admin",
        severity="medium",
        confidence=0.8,
        status="approved",
    )
    session.add(hypo)
    session.flush()

    session.add(WorkflowStep(
        hypothesis_id=hypo.id,
        state="validated",
        actor="system",
        notes="confirmed via trace",
    ))
    session.add(Evidence(
        id="ev-trace",
        hypothesis_id=hypo.id,
        type="screenshot",
        data="proof-bytes",
        metadata_json={"source": "unit-test"},
        hash_sha256="abc123",
    ))
    DecisionRepository(session).save(
        Decision(
            session_id="session-trace",
            decision_type="prioritize_host",
            target="trace.example.com",
            reason="signal present",
            context={"signal": "open_port"},
            reputation_weight=0.7,
            novelty_weight=0.2,
            diff_weight=0.1,
        )
    )
    session.commit()

    with patch("src.core.api.SessionLocal", return_value=session):
        trace = get_session_trace("session-trace")

    assert trace["session_id"] == "session-trace"
    assert trace["target"] == "trace.example.com"
    assert trace["summary"]["decisions"] == 1
    assert trace["summary"]["evidence_items"] == 1
    assert trace["scan"]["stats"]["findings"] == 1
    assert trace["workflow_steps"][0]["state"] == "validated"
    assert trace["evidence"][0]["metadata"]["source"] == "unit-test"
    assert trace["decisions"][0]["context"]["signal"] == "open_port"

    session.close()
