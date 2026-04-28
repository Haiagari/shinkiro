
import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch
from cli.commands.report import report
import os

class TestReportCLI:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    @patch('cli.commands.report.SessionLocal')
    @patch('cli.commands.report.Jinja2ReportEngine')
    @patch('cli.commands.report.ensure_config_loaded', lambda: lambda x: x) # Skip config decorator
    @patch('cli.commands.report.handle_exception', lambda e: print(e)) # Mock handle_exception
    @patch('cli.ozy.config')
    def test_report_success_html(self, mock_config, mock_engine_cls, mock_session, runner, tmp_path):
        """Test 'ozy report' success generating HTML."""
        # Setup mock config to pass ensure_config_loaded
        mock_config.threads = 10
        mock_config.output_dir = "results"
        
        # Mock DB target check
        mock_db = MagicMock()
        mock_session.return_value = mock_db
        mock_target = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_target
        
        # Mock Engine
        mock_engine = MagicMock()
        mock_engine_cls.return_value = mock_engine
        report_file = tmp_path / "report_test.html"
        mock_engine.generate_report.return_value = str(report_file)
        
        result = runner.invoke(report, ['test.com', '--format', 'html', '--output', str(tmp_path)])
        
        assert result.exit_code == 0
        assert "Report generated successfully" in result.output
        assert str(report_file) in result.output

    @patch('cli.commands.report.SessionLocal')
    @patch('cli.commands.report.ensure_config_loaded', lambda: lambda x: x)
    @patch('cli.ozy.config')
    def test_report_target_not_found(self, mock_config, mock_session, runner):
        """Test 'ozy report' with nonexistent target."""
        mock_config.threads = 10
        mock_config.output_dir = "results"
        
        mock_db = MagicMock()
        mock_session.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = None
        
        result = runner.invoke(report, ['nonexistent.com'])
        
        assert result.exit_code == 1
        assert "Error: Target 'nonexistent.com' not found" in result.output

    @patch('cli.commands.report.SessionLocal')
    @patch('cli.commands.report.Jinja2ReportEngine')
    @patch('cli.commands.report.ensure_config_loaded', lambda: lambda x: x)
    @patch('cli.ozy.config')
    def test_report_both_formats(self, mock_config, mock_engine_cls, mock_session, runner, tmp_path):
        """Test 'ozy report' with --format both."""
        mock_config.threads = 10
        mock_config.output_dir = "results"
        
        mock_db = MagicMock()
        mock_session.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = MagicMock()
        
        mock_engine = MagicMock()
        mock_engine_cls.return_value = mock_engine
        mock_engine.generate_report.return_value = "/tmp/report.html"
        
        result = runner.invoke(report, ['test.com', '--format', 'both', '--output', str(tmp_path)])
        
        assert result.exit_code == 0
        assert "All report formats saved in" in result.output

    @patch('cli.commands.report.SessionLocal')
    @patch('cli.commands.report.Jinja2ReportEngine')
    @patch('cli.commands.report.ensure_config_loaded', lambda: lambda x: x)
    @patch('cli.ozy.config')
    def test_report_engine_failure(self, mock_config, mock_engine_cls, mock_session, runner):
        """Test 'ozy report' when engine returns None (failure)."""
        mock_config.threads = 10
        mock_config.output_dir = "results"
        
        mock_db = MagicMock()
        mock_session.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = MagicMock()
        
        mock_engine = MagicMock()
        mock_engine_cls.return_value = mock_engine
        mock_engine.generate_report.return_value = None
        
        result = runner.invoke(report, ['test.com'])
        
        assert result.exit_code == 1
        assert "Failed to generate report" in result.output
