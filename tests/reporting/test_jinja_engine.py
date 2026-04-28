
import pytest
from unittest.mock import MagicMock, patch
from src.reporting.jinja_engine import Jinja2ReportEngine
from src.reporting.schemas import create_report_data

class TestJinja2ReportEngine:
    @pytest.fixture
    def engine(self):
        # We need a real template dir to initialize, or mock it
        # resources/reports/templates should exist from previous phases
        return Jinja2ReportEngine()

    def test_add_custom_filters(self, engine):
        """Test that custom filters are added to the environment."""
        engine._add_custom_filters()
        assert 'datetime' in engine.env.filters
        assert 'severity_sort' in engine.env.filters
        assert 'format_json' in engine.env.filters

    def test_datetime_filter(self, engine):
        """Test the datetime filter logic."""
        engine._add_custom_filters()
        fmt_date = engine.env.filters['datetime']
        
        # Test string ISO
        assert fmt_date("2026-04-27T10:00:00") == "April 27, 2026 10:00:00"
        # Test None
        assert fmt_date(None) == "N/A"
        # Test invalid string
        assert fmt_date("invalid") == "invalid"

    def test_severity_sort_filter(self, engine):
        """Test the severity_sort filter logic."""
        engine._add_custom_filters()
        sev_sort = engine.env.filters['severity_sort']
        
        data = {
            "high": [{"title": "H1"}],
            "critical": [{"title": "C1"}],
            "low": [{"title": "L1"}],
            "medium": []
        }
        
        sorted_list = sev_sort(data)
        assert sorted_list[0][0] == "critical"
        assert sorted_list[1][0] == "high"
        assert sorted_list[2][0] == "low"
        assert len(sorted_list) == 3 # medium is empty

    @patch('src.reporting.jinja_engine.SessionLocal')
    @patch('src.reporting.jinja_engine.get_scoring_engine')
    def test_gather_data_structure(self, mock_scoring, mock_session, engine):
        """Test that _gather_data returns the correct structure even if DB is empty."""
        mock_db = MagicMock()
        mock_session.return_value = mock_db
        
        # Mock target/scan not found
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.query.return_value.filter.return_value.all.return_value = []
        
        data = engine._gather_data("example.com")
        
        assert "scan_info" in data
        assert "findings" in data
        assert "scoring" in data
        assert "attack_paths" in data
        assert "summary" in data
        assert data["scan_info"]["target"] == "example.com"

    def test_render_html_basic(self, engine):
        """Test basic HTML rendering with mock data."""
        report_data = create_report_data("test.com")
        report_data["summary"]["total_findings"] = 0
        
        # Mock get_template to avoid file system dependency in this unit test if possible
        # but Jinja2ReportEngine uses self.env.get_template
        with patch.object(engine.env, 'get_template') as mock_get:
            mock_template = MagicMock()
            mock_template.render.return_value = "<html>Test</html>"
            mock_get.return_value = mock_template
            
            html = engine.render_html(report_data)
            assert html == "<html>Test</html>"
            mock_get.assert_called_once_with("layouts/report.j2")

    def test_render_html_invalid_data(self, engine):
        """Test that render_html raises error with None data."""
        with pytest.raises(ValueError, match="report_data cannot be None"):
            engine.render_html(None)

    def test_prepare_context_defaults(self, engine):
        """Test that _prepare_context fills in missing keys."""
        partial_data = {"scan_info": {"target": "test.com"}}
        context = engine._prepare_context(partial_data)
        
        assert "findings" in context
        assert "scoring" in context
        assert "attack_paths" in context
        assert "summary" in context
        assert context["findings"]["critical"] == []
