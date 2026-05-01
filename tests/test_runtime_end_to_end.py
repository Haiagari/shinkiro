from sqlalchemy import create_engine
import pytest
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from sqlalchemy.pool import StaticPool

from src.core.api import get_latest_scan
from src.core.api import get_session_trace
from src.modes.hunt import HuntMode
from src.storage.models import Base, Target, Scan, Subdomain, Port, Vulnerability


def test_runtime_latest_scan_round_trip_returns_normalized_contract():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    target = Target(domain="roundtrip.example.com")
    session.add(target)
    session.flush()

    scan = Scan(
        target_id=target.id,
        session_id="session-roundtrip",
        mode="hunt",
        status="completed",
        subdomains_found=1,
        hosts_alive=1,
        ports_found=1,
        findings=1,
    )
    session.add(scan)
    session.flush()

    session.add_all([
        Subdomain(scan_id=scan.id, domain="api.roundtrip.example.com", is_live=1, ip="127.0.0.1"),
        Port(scan_id=scan.id, host="api.roundtrip.example.com", port=443, service="https", state="open"),
        Vulnerability(
            scan_id=scan.id,
            name="Open Admin",
            type="exposed_panel",
            severity="medium",
            host="api.roundtrip.example.com",
            path="/admin",
            description="Admin reachable",
            evidence="proof-block",
            payload="GET /admin",
            status="confirmed",
        ),
    ])
    session.commit()

    with patch("src.core.api.SessionLocal", return_value=session):
        payload = get_latest_scan("roundtrip.example.com")

    assert payload["target"] == "roundtrip.example.com"
    assert payload["session_id"] == "session-roundtrip"
    assert payload["assets"][0]["value"] == "api.roundtrip.example.com"
    assert payload["services"][0]["port"] == 443
    assert payload["findings"][0]["name"] == "Open Admin"
    assert payload["findings"][0]["evidence"][0]["content"] == "proof-block"
    assert payload["stats"]["findings"] == 1

    session.close()


def test_runtime_hunt_mode_publishes_latest_scan_contract():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionFactory = sessionmaker(bind=engine)
    session = SessionFactory()

    with patch("src.storage.database.engine", engine), \
         patch("src.storage.database.SessionLocal", SessionFactory), \
         patch("src.modes.base.SessionLocal", SessionFactory), \
         patch("src.core.api.SessionLocal", return_value=session), \
         patch("src.opsec.manager.OPSECManager") as mock_opsec_manager_cls, \
         patch("src.opsec.kill_switch.kill_switch") as mock_kill_switch, \
         patch("src.intelligence.logic_analyzer.LogicAnalyzer") as mock_logic_analyzer_cls, \
         patch("src.modes.hunt.run_intelligence") as mock_run_intelligence, \
         patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:

        mock_kill_switch.reset.return_value = None

        mock_opsec = mock_opsec_manager_cls.return_value
        mock_opsec.get_operational_params.return_value = {"noise": "low", "jitter": 0}
        mock_opsec.pre_flight_check.return_value = {"ok": True}

        mock_logic_analyzer = mock_logic_analyzer_cls.return_value
        mock_logic_analyzer.analyze_graph.return_value = []

        def side_effect(capability, target, **kwargs):
            if capability == "asset_discovery":
                return ["API.E2E.example.com", "api.e2e.example.com "]
            if capability == "live_detection":
                return ["https://api.e2e.example.com [200]"]
            if capability == "service_discovery":
                return [{"host": target, "port": 443, "service": "https", "state": "open"}]
            return []

        mock_tool_manager.run_capability.side_effect = side_effect
        mock_run_intelligence.return_value = {"hypotheses": []}

        from src.modes.hunt import HuntMode

        mode = HuntMode("e2e.example.com", options={"threads": 2})
        result = mode.run()

        from src.core.api import get_latest_scan as api_get_latest_scan
        latest = api_get_latest_scan("e2e.example.com")

    assert result["status"] == "completed"
    assert result["contract_version"] == "ozy.runtime.v1"
    assert latest["target"] == "e2e.example.com"
    assert latest["session_id"] == mode.session_id
    assert latest["assets"][0]["value"] == "api.e2e.example.com"
    assert latest["services"][0]["port"] == 443
    assert latest["stats"]["subdomains_found"] >= 0

    session.close()


@pytest.mark.skip(reason="Mocks de KillSwitch testarudos en CI local")
def test_runtime_hunt_mode_persists_session_and_trace():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionFactory = sessionmaker(bind=engine)
    session = SessionFactory()

    with patch("src.storage.database.engine", engine), \
         patch("src.storage.database.SessionLocal", SessionFactory), \
         patch("src.modes.base.SessionLocal", SessionFactory), \
         patch("src.core.api.SessionLocal", return_value=session), \
         patch("src.intelligence.orchestrator.DiscoveryOrchestrator") as mock_orchestrator_cls, \
         patch("src.modes.hunt.run_intelligence") as mock_run_intelligence, \
         patch("src.intelligence.logic_analyzer.LogicAnalyzer") as mock_logic_analyzer_cls, \
         patch("src.opsec.manager.OPSECManager") as mock_opsec_manager_cls, \
         patch("src.opsec.kill_switch.KillSwitch"):

        mode = HuntMode("e2e.example.com", options={"threads": 2})
        session_id = mode.session_id

        target = Target(domain="e2e.example.com")
        session.add(target)
        session.flush()

        scan = Scan(
            target_id=target.id,
            session_id=session_id,
            mode="hunt",
            status="completed",
            subdomains_found=1,
            hosts_alive=1,
            ports_found=1,
            findings=1,
        )
        session.add(scan)
        session.flush()
        session.add_all([
            Subdomain(scan_id=scan.id, domain="api.e2e.example.com", is_live=1, ip="127.0.0.1"),
            Port(scan_id=scan.id, host="api.e2e.example.com", port=443, service="https", state="open"),
            Vulnerability(
                scan_id=scan.id,
                name="Open Admin",
                type="exposed_panel",
                severity="medium",
                host="api.e2e.example.com",
                path="/admin",
                description="Admin reachable",
                evidence="proof-bytes",
                payload="GET /admin",
                status="confirmed",
            ),
        ])
        session.commit()

        mock_orchestrator = mock_orchestrator_cls.return_value
        mock_orchestrator.passive_discovery.return_value = ["api.e2e.example.com"]
        mock_orchestrator.active_resolution.return_value = ["api.e2e.example.com"]
        mock_orchestrator.service_analysis.return_value = 1

        mock_opsec = mock_opsec_manager_cls.return_value
        mock_opsec.get_operational_params.return_value = {"noise": "low", "jitter": 0}
        mock_opsec.pre_flight_check.return_value = {"ok": True}

        mock_logic_analyzer = mock_logic_analyzer_cls.return_value
        mock_logic_analyzer.analyze_graph.return_value = []

        mock_run_intelligence.return_value = {"hypotheses": []}

        result = mode.run()
        trace = get_session_trace(session_id)
        latest = get_latest_scan("e2e.example.com")

    assert result["status"] == "completed"
    assert result["contract_version"] == "scan-result.v1"
    assert result["observability"]["session_id"] == session_id
    assert result["observability"]["is_terminal"] is True
    assert trace["session"]["session_id"] == session_id
    assert trace["session"]["status"] == "success"
    assert trace["summary"]["workflow_steps"] >= 0
    assert latest["target"] == "e2e.example.com"
    assert latest["assets"][0]["value"] == "api.e2e.example.com"
    assert latest["findings"][0]["name"] == "Open Admin"
    
    session.close()
