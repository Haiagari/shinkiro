from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.discovery.assets.recon import run_recon


def test_run_recon_matches_mixed_case_targets(tmp_path):
    args = SimpleNamespace(threads=1)

    def fake_run_capability(capability, target, **kwargs):
        if capability == "asset_discovery":
            return ["Api.Example.com", "example.com.au", "badexample.com", "Other.com"]
        if capability == "dns_resolution":
            return []
        if capability == "live_detection":
            return []
        if capability == "template_scan":
            return []
        raise AssertionError(f"Unexpected capability: {capability}")

    with patch("src.discovery.assets.recon.tool_manager") as mock_tool_manager:
        mock_tool_manager.run_capability.side_effect = fake_run_capability
        result = run_recon("Example.com", Path(tmp_path), args)

    assert result["all_subdomains"] == ["api.example.com", "example.com"]
