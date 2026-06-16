from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.discovery.services.ports import run_ports, TOP_PORTS


def _count_calls(mock, capability: str) -> int:
    return sum(1 for args, _ in mock.call_args_list if args[0] == capability)


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

    assert _count_calls(mock_tool_manager.run_capability, "port_scan") == 2
    assert _count_calls(mock_tool_manager.run_capability, "service_discovery") == 2
    mock_tool_manager.run_capability.assert_any_call("port_scan", "a.example.com", ports=TOP_PORTS)
    mock_tool_manager.run_capability.assert_any_call("port_scan", "b.example.com", ports=TOP_PORTS)
    assert result["open_ports"] == ["a.example.com:80", "b.example.com:443"]


def test_run_ports_normalizes_url_inputs(tmp_path):
    hosts = ["https://a.example.com:8443/path?x=1", "http://b.example.com:8080/path"]
    args = SimpleNamespace(max_hosts=None)

    with patch("src.discovery.services.ports.tool_manager") as mock_tool_manager:

        def side_effect(capability, target, **kwargs):
            if capability == "port_scan":
                if target in ("a.example.com", "b.example.com"):
                    return []
                raise AssertionError("port_scan called for an unexpected host")
            if capability == "service_discovery":
                return []
            raise AssertionError(f"Unexpected capability: {capability}")

        mock_tool_manager.run_capability.side_effect = side_effect

        run_ports(hosts, Path(tmp_path), args, context={})

    assert _count_calls(mock_tool_manager.run_capability, "port_scan") == 2
    assert _count_calls(mock_tool_manager.run_capability, "service_discovery") == 0
    mock_tool_manager.run_capability.assert_any_call("port_scan", "a.example.com", ports=TOP_PORTS)
    mock_tool_manager.run_capability.assert_any_call("port_scan", "b.example.com", ports=TOP_PORTS)
