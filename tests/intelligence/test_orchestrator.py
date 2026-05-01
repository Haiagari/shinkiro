import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.storage.models import Base, Subdomain, Port, Hypothesis
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
    assets = [
        {"domain": "test.com", "is_live": 1, "ip": "0.0.0.0"}
    ]
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
    assets = [
        {"domain": "update.com", "is_live": 1, "ip": "0.0.0.0"}
    ]
    orchestrator._upsert_assets(assets)
    
    subs = db_session.query(Subdomain).filter_by(domain="update.com").all()
    assert len(subs) == 1
    assert subs[0].ip == "0.0.0.0"
    assert subs[0].is_live == 1

def test_upsert_assets_handles_multiple_assets(orchestrator, db_session):
    """
    RED: Test should fail because _upsert_assets is not implemented.
    """
    assets = [
        {"domain": "a.com", "ip": "0.0.0.0"},
        {"domain": "b.com", "ip": "0.0.0.0"}
    ]
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
        mock_tool_manager.run_capability.return_value = ["SUB1.test.com", "sub1.test.com ", "sub2.test.com"]
        
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
        mock_tool_manager.run_capability.assert_called_with(
            "service_discovery", "live.test.com"
        )
        
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
        assert sub2.is_live == 0 # No estaba en live_detection results
        
        # Verify port scan only ran for sub1
        assert db_session.query(Port).count() == 1
        port = db_session.query(Port).filter_by(host="sub1.test.com").first()
        assert port is not None
        assert port.port == 443


def test_passive_discovery_returns_normalized_subdomains(orchestrator, db_session):
    with patch("src.intelligence.orchestrator.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.return_value = ["SUB1.test.com", "sub1.test.com ", "sub2.test.com"]

        result = orchestrator.passive_discovery("test.com")

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

    with patch("src.workflow.orchestrator.workflow_engine.transition_hypothesis") as mock_transition, \
         patch("src.workflow.orchestrator.validation_policy.classify") as mock_classify, \
         patch("src.workflow.orchestrator.AuthValidator.validate") as mock_validate, \
         patch("src.workflow.orchestrator.SessionLocal", return_value=db_session):
        mock_classify.return_value.action = "gate_required"
        mock_classify.return_value.requires_gate = True
        mock_classify.return_value.is_blocked = False
        mock_classify.return_value.reason = "DEFAULT_AUTH should remain explicitly gated"
        mock_validate.return_value = MagicMock(status="confirmed", confidence_after=0.9, evidence=[], notes="ok")

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

    with patch("src.workflow.orchestrator.workflow_engine.transition_hypothesis") as mock_transition, \
         patch("src.workflow.orchestrator.validation_policy.classify") as mock_classify, \
         patch("src.workflow.orchestrator.AuthValidator.validate") as mock_validate, \
         patch("src.workflow.orchestrator.SessionLocal", return_value=db_session):
        mock_classify.return_value.action = "gate_required"
        mock_classify.return_value.requires_gate = True
        mock_classify.return_value.is_blocked = False
        mock_classify.return_value.reason = "DEFAULT_AUTH should remain explicitly gated"
        mock_validate.return_value = MagicMock(status="confirmed", confidence_after=0.9, evidence=[], notes="ok")

        workflow_orchestrator.validate_hypothesis(hypo)

        mock_validate.assert_called_once()
        mock_transition.assert_any_call(hyp_id, WorkflowState.VALIDATING, notes="Starting automated validation")
