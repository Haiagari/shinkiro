from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.discovery.services.ports import run_ports


def test_run_ports_respects_explicit_max_hosts(tmp_path):
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    args = SimpleNamespace(max_hosts=None)

    with patch("src.discovery.services.ports.tool_manager") as mock_tool_manager:

        def side_effect(capability, target, **kwargs):
            if capability == "port_scan":
                if target == "a.example.com":
                    return [SimpleNamespace(host="a.example.com", port=80)]
                if target == "b.example.com":
                    return [SimpleNamespace(host="b.example.com", port=443)]
                raise AssertionError("port_scan called for an unexpected host")
            if capability == "service_discovery":
                return []
            raise AssertionError(f"Unexpected capability: {capability}")

        mock_tool_manager.run_capability.side_effect = side_effect

        result = run_ports(hosts, Path(tmp_path), args, context={"max_hosts": 2})

    assert mock_tool_manager.run_capability.call_count == 4
    assert mock_tool_manager.run_capability.call_args_list[0].args == ("port_scan", "a.example.com")
    assert mock_tool_manager.run_capability.call_args_list[1].args == ("port_scan", "b.example.com")
    assert result["open_ports"] == ["a.example.com:80", "b.example.com:443"]


def test_run_ports_normalizes_url_inputs(tmp_path):
    hosts = ["https://a.example.com:8443/path?x=1", "http://b.example.com:8080/path"]
    args = SimpleNamespace(max_hosts=None)

    with patch("src.discovery.services.ports.tool_manager") as mock_tool_manager:

        def side_effect(capability, target, **kwargs):
            if capability == "port_scan":
                if target == "a.example.com":
                    return []
                if target == "b.example.com":
                    return []
                raise AssertionError("port_scan called for an unexpected host")
            if capability == "service_discovery":
                return []
            raise AssertionError(f"Unexpected capability: {capability}")

        mock_tool_manager.run_capability.side_effect = side_effect

        run_ports(hosts, Path(tmp_path), args, context={})

    assert mock_tool_manager.run_capability.call_args_list[0].args == ("port_scan", "a.example.com")
    assert mock_tool_manager.run_capability.call_args_list[1].args == ("port_scan", "b.example.com")
