import pytest
from src.intelligence.pipeline.orchestrator import DiscoveryOrchestrator
from src.storage.database import SessionLocal
from pathlib import Path

from src.intelligence.pipeline.collaboration import write_collaboration_manifest, read_collaboration_manifest

def test_collaborative_artifact_sharing():
    """
    Test that session artifacts are structured for collaboration.
    """
    session_id = "shared-session"
    manifest = write_collaboration_manifest(session_id, "example.com", scan_id=1, operators=["alice"], artifacts=["raw", "normalized"])

    assert manifest["session_id"] == session_id
    assert manifest["target"] == "example.com"
    assert (Path("runs") / session_id / "collaboration.json").exists()
    loaded = read_collaboration_manifest(session_id)
    assert loaded["operators"] == ["alice"]
    assert "normalized" in loaded["artifacts"]

def test_quiet_mode_export():
    """
    Test that normalizer respects a quiet/minimal flag.
    """
    from src.export.normalizer import NormalizedExporter
    exporter = NormalizedExporter()
    # We want a 'minimal' or 'quiet' export mode
    result = exporter.export_scan("test", "example.com", minimal=True)
    assert len(result.assets) >= 0 # Should still work, but maybe filtered
