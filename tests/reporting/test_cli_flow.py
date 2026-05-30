import json
from pathlib import Path
from unittest.mock import patch

from cli.commands.flow import _build_data_summary_lines, execute_flow


def test_execute_flow_writes_summary(tmp_path):
    report_path = tmp_path / "report.html"

    with patch("cli.commands.flow._collect_verification") as mock_verify, \
         patch("cli.commands.flow._run_hunt") as mock_hunt, \
         patch("cli.commands.flow._build_analysis_snapshot") as mock_analysis, \
         patch("cli.commands.flow._write_analysis_files") as mock_write_analysis, \
         patch("cli.commands.flow._generate_dummy_report") as mock_report:

        mock_verify.return_value = {
            "allow_degraded": False,
            "passed": True,
            "checks": [{"name": "Python version", "ok": True}],
        }
        mock_hunt.return_value = {
            "status": "completed",
            "session_id": "sid123",
            "target": "test.com",
        }
        mock_analysis.return_value = {
            "status": "generated",
            "target": "test.com",
            "session_id": "sid123",
            "analysis": "summary",
            "recommendations": ["fix me"],
        }
        mock_write_analysis.return_value = {
            "analysis_md": str(tmp_path / "analysis.md"),
            "analysis_json": str(tmp_path / "analysis.json"),
        }
        mock_report.return_value = None

        with patch("cli.commands.flow.tool_manager.get_timing_summary", return_value={"count": 1, "total_elapsed": 0.2, "slowest_tools": []}):
            summary = execute_flow("test.com", output=str(tmp_path))

    assert summary["status"] == "completed"
    assert summary["session_id"] == "sid123"
    assert summary["artifacts"]["report"] is None
    assert summary["timing"]["count"] == 1

    saved_summary = Path(tmp_path / "test.com" / "sid123" / "flow_summary.json")
    assert saved_summary.exists()
    data = json.loads(saved_summary.read_text())
    assert data["session_id"] == "sid123"
    assert data["artifacts"]["report"] is None
    assert data["timing"]["count"] == 1


def test_build_data_summary_lines_includes_key_counts():
    lines = _build_data_summary_lines(
        {
            "target": "example.com",
            "analysis": {
                "live_subdomains": ["example.com", "a.example.com", "b.example.com"],
                "open_ports": [
                    {"port": 22},
                    {"port": 80},
                    {"port": 3306},
                ],
                "recommendations": ["one", "two"],
            },
        }
    )

    joined = "\n".join(lines)
    assert "Live hosts" in joined
    assert "Open ports" in joined
    assert "Critical services" in joined
    assert "High-value hosts" in joined
    assert "Recommendations" in joined
