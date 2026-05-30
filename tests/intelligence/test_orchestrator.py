import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.storage.models import Base, Subdomain, Port, Hypothesis, Target, Scan
from src.intelligence.orchestrator import DiscoveryOrchestrator
from src.workflow.orchestrator import WorkflowOrchestrator
from unittest.mock import MagicMock, patch
from src.workflow.states import WorkflowState


# Setup in-memory SQLite for testing
@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def orchestrator(db_session):
    return DiscoveryOrchestrator(db_session)


def test_upsert_assets_inserts_new_subdomain(orchestrator, db_session):
    """
    RED: Test should fail because _upsert_assets is not implemented.
    """
    assets = [{"domain": "test.com", "is_live": 1, "ip": "0.0.0.0"}]
    orchestrator._upsert_assets(assets)

    sub = db_session.query(Subdomain).filter_by(domain="test.com").first()
    assert sub is not None
    assert sub.ip == "0.0.0.0"


def test_upsert_assets_updates_existing_subdomain(orchestrator, db_session):
    """
    RED: Test should fail because _upsert_assets is not implemented.
    """
    # Initial insert
    sub1 = Subdomain(domain="update.com", ip="0.0.0.0", is_live=0)
    db_session.add(sub1)
    db_session.commit()

    # Update
    assets = [{"domain": "update.com", "is_live": 1, "ip": "0.0.0.0"}]
    orchestrator._upsert_assets(assets)

    subs = db_session.query(Subdomain).filter_by(domain="update.com").all()
    assert len(subs) == 1
    assert subs[0].ip == "0.0.0.0"
    assert subs[0].is_live == 1


def test_upsert_assets_handles_multiple_assets(orchestrator, db_session):
    """
    RED: Test should fail because _upsert_assets is not implemented.
    """
    assets = [{"domain": "a.com", "ip": "0.0.0.0"}, {"domain": "b.com", "ip": "0.0.0.0"}]
    orchestrator._upsert_assets(assets)

    assert db_session.query(Subdomain).count() == 2


def test_passive_discovery_calls_tool_manager(orchestrator, db_session):
    """
    RED: Test for passive_discovery implementation.
    """
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = ["sub1.test.com", "sub2.test.com"]

        result = orchestrator.passive_discovery("test.com")

        # Verify it called run_capability for asset_discovery
        mock_tool_manager.run_capability.assert_called_with(
            "asset_discovery", "test.com", all_providers=True
        )

        # Verify results were persisted
        assert db_session.query(Subdomain).count() == 2
        assert db_session.query(Subdomain).filter_by(domain="sub1.test.com").first() is not None
        assert sorted(result) == ["sub1.test.com", "sub2.test.com"]


def test_passive_discovery_deduplicates_and_normalizes(orchestrator, db_session):
    """
    TRIANGULATE: Test deduplication and normalization in passive_discovery.
    """
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = [
            "SUB1.test.com",
            "sub1.test.com ",
            "sub2.test.com",
        ]

        orchestrator.passive_discovery("test.com")

        # Should only have 2 unique normalized subdomains
        assert db_session.query(Subdomain).count() == 2
        assert db_session.query(Subdomain).filter_by(domain="sub1.test.com").count() == 1


def test_active_resolution_calls_tool_manager(orchestrator, db_session):
    """
    RED: Test for active_resolution implementation.
    """
    # Setup existing assets
    db_session.add(Subdomain(domain="sub1.test.com"))
    db_session.add(Subdomain(domain="sub2.test.com"))
    db_session.commit()

    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        # Mock httpx output (v7.1 expects JSON lines)
        import json

        mock_tool_manager.run_capability.return_value = [
            json.dumps({"url": "http://sub1.test.com", "status_code": 200, "tech": ["Nginx"]}),
        ]

        # We need to mock how it reads assets to resolve
        orchestrator.active_resolution()

        # Verify it called run_capability for live_detection
        mock_tool_manager.run_capability.assert_called()

        # Verify sub1 is now marked as live
        sub1 = db_session.query(Subdomain).filter_by(domain="sub1.test.com").first()
        assert sub1.is_live == 1


def test_active_resolution_handles_various_url_formats(orchestrator, db_session):
    """
    TRIANGULATE: Test active_resolution parsing with different output formats.
    """
    db_session.add(Subdomain(domain="sub1.test.com"))
    db_session.add(Subdomain(domain="sub2.test.com"))
    db_session.add(Subdomain(domain="sub3.test.com"))
    db_session.commit()

    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        import json

        mock_tool_manager.run_capability.return_value = [
            json.dumps({"url": "https://sub1.test.com", "status_code": 200}),
            json.dumps({"url": "http://sub2.test.com:8080", "status_code": 200}),
            json.dumps({"url": "http://sub3.test.com", "status_code": 200}),
        ]

        orchestrator.active_resolution()

        assert db_session.query(Subdomain).filter_by(domain="sub1.test.com").first().is_live == 1
        assert db_session.query(Subdomain).filter_by(domain="sub2.test.com").first().is_live == 1
        assert db_session.query(Subdomain).filter_by(domain="sub3.test.com").first().is_live == 1


def test_service_analysis_calls_nmap_on_live_assets(orchestrator, db_session):
    """
    RED: Test service_analysis implementation.
    """
    # Setup live asset
    db_session.add(Subdomain(domain="live.test.com", is_live=1))
    db_session.add(Subdomain(domain="dead.test.com", is_live=0))
    db_session.commit()

    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        # NmapProvider returns a list of Port objects or dicts
        # According to design it uses Port model
        mock_tool_manager.run_capability.return_value = [
            {"host": "live.test.com", "port": 80, "service": "http", "state": "open"}
        ]

        orchestrator.service_analysis()

        # Verify it called run_capability for service_discovery
        mock_tool_manager.run_capability.assert_called_with("service_discovery", "live.test.com")

        # Verify port was persisted
        assert db_session.query(Port).count() == 1
        port = db_session.query(Port).filter_by(host="live.test.com", port=80).first()
        assert port is not None
        assert port.service == "http"


def test_complete_orchestrator_flow(orchestrator, db_session):
    """
    RED: Test complete flow Passive -> Active -> Service.
    """
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        # 1. Passive finds subdomains
        def side_effect(capability, target, **kwargs):
            import json

            if capability == "asset_discovery":
                return ["sub1.test.com", "sub2.test.com"]
            if capability == "live_detection":
                return [json.dumps({"url": "http://sub1.test.com", "status_code": 200})]
            if capability == "service_discovery":
                return [{"host": target, "port": 443, "service": "https"}]
            return []

        mock_tool_manager.run_capability.side_effect = side_effect

        # Run flow
        orchestrator.passive_discovery("test.com")
        orchestrator.active_resolution()
        orchestrator.service_analysis()

        # Verify Results
        assert db_session.query(Subdomain).count() == 2
        sub1 = db_session.query(Subdomain).filter_by(domain="sub1.test.com").first()
        assert sub1.is_live == 1

        sub2 = db_session.query(Subdomain).filter_by(domain="sub2.test.com").first()
        assert sub2.is_live == 0  # No estaba en live_detection results

        # Verify port scan ran for sub1 (should have at least 1 port from httpx fallback + maybe nmap)
        assert db_session.query(Port).count() >= 1
        port = db_session.query(Port).filter_by(host="sub1.test.com").first()
        assert port is not None
        assert port.port in [80, 443]


def test_orchestrator_scopes_resolution_and_service_analysis_to_current_scan(db_session):
    target_a = Target(domain="a.example.com")
    target_b = Target(domain="b.example.com")
    db_session.add_all([target_a, target_b])
    db_session.commit()

    scan_a = Scan(target_id=target_a.id, session_id="sess-a", mode="hunt")
    scan_b = Scan(target_id=target_b.id, session_id="sess-b", mode="hunt")
    db_session.add_all([scan_a, scan_b])
    db_session.commit()

    db_session.add_all(
        [
            Subdomain(scan_id=scan_a.id, domain="live-a.example.com", is_live=1),
            Subdomain(scan_id=scan_b.id, domain="live-b.example.com", is_live=1),
        ]
    )
    db_session.commit()

    orchestrator = DiscoveryOrchestrator(db_session, scan_id=scan_a.id)

    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:

        def live_side_effect(capability, target, **kwargs):
            if capability == "live_detection":
                with open(target, "r", encoding="utf-8") as fh:
                    data = fh.read()
                assert "live-a.example.com" in data
                assert "live-b.example.com" not in data
                import json

                return [json.dumps({"url": "http://live-a.example.com", "status_code": 200})]
            if capability == "service_discovery":
                assert target == "live-a.example.com"
                return [{"host": target, "port": 80, "service": "http", "state": "open"}]
            return []

        mock_tool_manager.run_capability.side_effect = live_side_effect

        resolved = orchestrator.active_resolution()
        ports = orchestrator.service_analysis()

    assert resolved == ["live-a.example.com"]
    assert ports == 1
    assert db_session.query(Port).filter_by(host="live-a.example.com").count() == 1
    assert db_session.query(Port).filter_by(host="live-b.example.com").count() == 0


def test_finalize_session_writes_collaboration_manifest_and_notifies(
    tmp_path, monkeypatch, db_session
):
    monkeypatch.chdir(tmp_path)

    target = Target(domain="final.example.com")
    db_session.add(target)
    db_session.commit()

    scan = Scan(target_id=target.id, session_id="sess-final", mode="hunt")
    db_session.add(scan)
    db_session.commit()

    orchestrator = DiscoveryOrchestrator(db_session, scan_id=scan.id)

    class DummyResult:
        def to_dict(self):
            return {"session_id": "sess-final", "stats": {"findings": 0}, "findings": []}

    monkeypatch.setattr(
        "src.export.normalizer.NormalizedExporter.export_scan",
        lambda self, *args, **kwargs: DummyResult(),
    )
    monkeypatch.setattr(
        "src.intelligence.graph_builder.graph_builder.build_scan_graph",
        lambda *args, **kwargs: {"nodes": [], "edges": []},
    )
    monkeypatch.setattr(
        "src.storage.queries.DBQueries.get_session_trace", lambda *args, **kwargs: {"trace": []}
    )

    calls = []

    monkeypatch.setattr("src.intelligence.orchestrator.notifier.is_configured", lambda: True)
    monkeypatch.setattr(
        "src.intelligence.orchestrator.notifier.send_scan_summary",
        lambda target, result: calls.append((target, result.to_dict())) or True,
    )

    orchestrator.finalize_session()

    manifest_path = tmp_path / "runs" / "sess-final" / "collaboration.json"
    assert manifest_path.exists()
    assert calls and calls[0][0] == "final.example.com"


def test_passive_discovery_returns_normalized_subdomains(orchestrator, db_session):
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = [
            "SUB1.test.com",
            "sub1.test.com ",
            "sub2.test.com",
        ]

        result = orchestrator.passive_discovery("test.com")

        assert sorted(result) == ["sub1.test.com", "sub2.test.com"]


def test_passive_discovery_filters_unrelated_domains(orchestrator, db_session):
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = [
            "sub1.test.com",
            "evil-corp.com",
            "api.evil-corp.com",
            "sub2.test.com",
        ]

        result = orchestrator.passive_discovery("test.com")

        assert sorted(result) == ["sub1.test.com", "sub2.test.com"]
        assert db_session.query(Subdomain).filter_by(domain="evil-corp.com").count() == 0
        assert db_session.query(Subdomain).filter_by(domain="api.evil-corp.com").count() == 0


def test_passive_discovery_normalizes_trailing_dot_targets(orchestrator):
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = ["SUB1.TEST.COM.", "sub2.test.com"]

        result = orchestrator.passive_discovery("TEST.COM.")

        assert sorted(result) == ["sub1.test.com", "sub2.test.com"]


def test_validate_hypothesis_defers_gate_required_until_approved(db_session):
    workflow_orchestrator = WorkflowOrchestrator()
    hypo = Hypothesis(
        id="hypo-gate-1",
        target_id=1,
        type="DEFAULT_AUTH",
        url="https://auth.example.com/login",
        confidence=0.6,
        status=WorkflowState.ANALYZED,
    )
    db_session.add(hypo)
    db_session.commit()

    with (
        patch("src.workflow.orchestrator.workflow_engine.transition_hypothesis") as mock_transition,
        patch("src.workflow.orchestrator.validation_policy.classify") as mock_classify,
        patch("src.workflow.orchestrator.AuthValidator.validate") as mock_validate,
        patch("src.workflow.orchestrator.SessionLocal", return_value=db_session),
    ):
        mock_classify.return_value.action = "gate_required"
        mock_classify.return_value.requires_gate = True
        mock_classify.return_value.is_blocked = False
        mock_classify.return_value.reason = "DEFAULT_AUTH should remain explicitly gated"
        mock_validate.return_value = MagicMock(
            status="confirmed", confidence_after=0.9, evidence=[], notes="ok"
        )

        workflow_orchestrator.validate_hypothesis(hypo)

        mock_transition.assert_called_once()
        mock_validate.assert_not_called()


def test_validate_hypothesis_allows_gate_required_after_manual_approval(db_session):
    workflow_orchestrator = WorkflowOrchestrator()
    hyp_id = "hypo-gate-2"
    hypo = Hypothesis(
        id=hyp_id,
        target_id=1,
        type="DEFAULT_AUTH",
        url="https://auth.example.com/login",
        confidence=0.6,
        status=WorkflowState.APPROVED,
    )
    db_session.add(hypo)
    db_session.commit()

    with (
        patch("src.workflow.orchestrator.workflow_engine.transition_hypothesis") as mock_transition,
        patch("src.workflow.orchestrator.validation_policy.classify") as mock_classify,
        patch("src.workflow.orchestrator.AuthValidator.validate") as mock_validate,
        patch("src.workflow.orchestrator.SessionLocal", return_value=db_session),
    ):
        mock_classify.return_value.action = "gate_required"
        mock_classify.return_value.requires_gate = True
        mock_classify.return_value.is_blocked = False
        mock_classify.return_value.reason = "DEFAULT_AUTH should remain explicitly gated"
        mock_validate.return_value = MagicMock(
            status="confirmed", confidence_after=0.9, evidence=[], notes="ok"
        )

        workflow_orchestrator.validate_hypothesis(hypo)

        mock_validate.assert_called_once()
        mock_transition.assert_any_call(
            hyp_id, WorkflowState.VALIDATING, notes="Starting automated validation"
        )
