
import pytest
import os
from unittest.mock import MagicMock, patch
from src.reporting.pdf_generator import PDFGenerator

class TestPDFGenerator:
    @pytest.fixture
    def generator(self, tmp_path):
        return PDFGenerator(output_path=str(tmp_path))

    def test_init_creates_dir(self, tmp_path):
        out = tmp_path / "new_reports"
        PDFGenerator(output_path=str(out))
        assert out.exists()

    def test_check_weasyprint(self, generator):
        # This depends on the environment, but we can verify it returns a bool
        assert isinstance(generator.weasyprint_available, bool)

    @patch('weasyprint.HTML')
    def test_generate_success(self, mock_html_cls, generator, tmp_path):
        if not generator.weasyprint_available:
            pytest.skip("WeasyPrint not available")
            
        mock_html = MagicMock()
        mock_html_cls.return_value = mock_html
        
        # Create a dummy file to simulate success
        filename = "test.pdf"
        full_path = os.path.join(generator.output_path, filename)
        with open(full_path, "wb") as f:
            f.write(b"%PDF-1.4 mock")

        with patch.object(generator, '_custom_url_fetcher') as mock_fetch:
            path = generator.generate("<html>Test</html>", output_filename=filename)
            assert path == os.path.abspath(full_path)
            mock_html_cls.assert_called_once()

    def test_generate_no_weasyprint_raises(self, generator):
        with patch.object(generator, 'weasyprint_available', False):
            with pytest.raises(RuntimeError, match="WeasyPrint is not installed"):
                generator.generate("<html>Test</html>")

    @patch('src.reporting.pdf_generator.os.path.exists')
    def test_custom_url_fetcher_resolves_static(self, mock_exists, generator):
        if not generator.weasyprint_available:
            pytest.skip("WeasyPrint not available")
            
        mock_exists.return_value = True
        
        with patch('builtins.open', MagicMock()) as mock_open:
            mock_file = mock_open.return_value.__enter__.return_value
            mock_file.read.return_value = b"body { color: red; }"
            
            # Should not raise
            result = generator._custom_url_fetcher("style.css")
            assert "mime_type" in result
            assert result["mime_type"] == "text/css"
            assert result["string"] == b"body { color: red; }"

    def test_fallback_behavior_in_engine(self, tmp_path):
        """
        Test that Jinja2ReportEngine handles PDF failure by falling back to HTML.
        This tests the integration between Engine and Generator failure.
        """
        from src.reporting.jinja_engine import Jinja2ReportEngine
        
        engine = Jinja2ReportEngine()
        engine.pdf_generator.output_path = str(tmp_path)
        
        # Force PDF generation to fail
        with patch.object(engine.pdf_generator, 'generate', side_effect=RuntimeError("PDF Error")), \
             patch.object(engine, '_gather_data', return_value=create_report_data("test.com")), \
             patch.object(engine, 'render_html', return_value="<html>Fallback</html>"):
            
            # Should return HTML path and print warning
            path = engine.generate_report("test.com", format="pdf")
            
            assert path.endswith(".html")
            assert os.path.exists(path)
            with open(path, "r") as f:
                assert f.read() == "<html>Fallback</html>"

def create_report_data(target):
    return {
        "scan_info": {"target": target, "timestamp": "now", "ozy_version": "1.0"},
        "findings": {"critical": [], "high": [], "medium": [], "low": []},
        "scoring": [],
        "attack_paths": [],
        "summary": {"total_findings": 0, "risk_score": 0.0},
        "charts": {},
        "custom": {}
    }
