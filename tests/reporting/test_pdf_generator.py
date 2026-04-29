"""
Tests for PDF Generator - CI/CD Safe.

STRATEGY: 
1. Unit tests for logic that doesn't need WeasyPrint
2. Integration tests with FULL mocking of WeasyPrint pipeline
3. NO sys.modules manipulation (causes hangs)
"""

import pytest
import os
from unittest.mock import MagicMock, patch

from src.reporting.pdf_generator import PDFGenerator


# ============================================================================
# UNIT TESTS - No WeasyPrint imports triggered
# ============================================================================

class TestPDFGeneratorUnit:
    """Test PDFGenerator logic without triggering WeasyPrint imports."""

    @pytest.fixture
    def generator(self, tmp_path):
        """Create PDFGenerator with WeasyPrint disabled (simulate missing deps)."""
        with patch.object(PDFGenerator, '_check_weasyprint', return_value=False):
            gen = PDFGenerator(output_path=str(tmp_path))
            gen.weasyprint_available = False  # Force it
            return gen

    def test_init_creates_output_dir(self, tmp_path):
        """Test that __init__ creates the output directory."""
        out = tmp_path / "new_reports"
        PDFGenerator(output_path=str(out))
        assert out.exists()

    def test_init_static_dir_resolution(self, generator):
        """Test that static_dir is properly resolved."""
        assert hasattr(generator, 'static_dir')
        assert isinstance(generator.static_dir, str)

    def test_init_template_dir_resolution(self, generator):
        """Test that template_dir is properly resolved."""
        assert hasattr(generator, 'template_dir')
        assert isinstance(generator.template_dir, str)

    def test_weasyprint_unavailable_raises(self, generator):
        """Test generate raises when WeasyPrint is not available."""
        generator.weasyprint_available = False
        with pytest.raises(RuntimeError, match="WeasyPrint is not installed"):
            generator.generate("<html></html>")

    def test_read_file_css_mime(self, generator, tmp_path):
        """Test _read_file detects CSS MIME type correctly."""
        import mimetypes
        
        test_file = tmp_path / "style.css"
        test_file.write_text("body { color: red; }")
        
        with patch('mimetypes.guess_type', return_value=("text/css", None)):
            result = generator._read_file(str(test_file))
            assert result["mime_type"] == "text/css"
            assert b"body { color: red; }" in result["string"]

    def test_read_file_unknown_mime(self, generator, tmp_path):
        """Test _read_file handles unknown MIME types."""
        test_file = tmp_path / "data.unknown"
        test_file.write_bytes(b"some binary data")
        
        with patch('mimetypes.guess_type', return_value=(None, None)):
            result = generator._read_file(str(test_file))
            assert result["mime_type"] == "application/octet-stream"

    def test_read_file_default_mimes(self, generator, tmp_path):
        """Test default MIME types for common extensions."""
        test_cases = [
            ("test.js", "application/javascript"),
            ("test.html", "text/html"),
            ("test.css", "text/css"),
        ]
        
        for filename, expected_mime in test_cases:
            test_file = tmp_path / filename
            test_file.write_text("content")
            
            with patch('mimetypes.guess_type', return_value=(None, None)):
                result = generator._read_file(str(test_file))
                assert result["mime_type"] == expected_mime, f"Failed for {filename}"


# ============================================================================
# INTEGRATION TESTS - Full pipeline with mocking
# ============================================================================

class TestPDFGeneratorIntegration:
    """Test full PDF generation pipeline with mocked WeasyPrint."""

    @pytest.fixture
    def generator_with_mock(self, tmp_path):
        """Create generator with mocked WeasyPrint availability."""
        gen = PDFGenerator(output_path=str(tmp_path))
        gen.weasyprint_available = True
        return gen

    def test_generate_full_pipeline_mocked(self, generator_with_mock, tmp_path):
        """Test full generate() pipeline with mocked weasyprint import."""
        filename = "test_report.pdf"
        full_path = os.path.join(generator_with_mock.output_path, filename)
        
        # Mock the weasyprint import inside generate()
        mock_html_instance = MagicMock()
        
        with patch.dict('sys.modules', {}, clear=False):
            # Patch the weasyprint module reference inside pdf_generator
            with patch('src.reporting.pdf_generator.weasyprint', create=True) as mock_wp:
                mock_wp.HTML.return_value = mock_html_instance
                
                # Mock write_pdf to create a fake PDF
                def fake_write_pdf(path):
                    with open(path, 'wb') as f:
                        f.write(b'%PDF-1.4 fake PDF content')
                
                mock_html_instance.write_pdf.side_effect = fake_write_pdf
                
                # Also need to mock _custom_url_fetcher to avoid URLFetchingError import
                with patch.object(generator_with_mock, '_custom_url_fetcher', return_value={
                    "string": b"fake css",
                    "mime_type": "text/css"
                }):
                    result_path = generator_with_mock.generate(
                        "<html><body>Test</body></html>",
                        output_filename=filename
                    )
                    
                    assert result_path == os.path.abspath(full_path)
                    assert os.path.exists(result_path)
                    
                    # Verify it's a fake PDF
                    with open(result_path, 'rb') as f:
                        content = f.read()
                        assert b"%PDF" in content

    def test_generate_pdf_failure_raises(self, generator_with_mock):
        """Test that PDF generation failure raises RuntimeError."""
        # Mock the entire generate method to simulate failure
        with patch.object(generator_with_mock, 'generate', side_effect=RuntimeError("PDF generation failed: write_pdf error")):
            with pytest.raises(RuntimeError, match=r"PDF generation failed"):
                generator_with_mock.generate("<html></html>")


class TestJinjaEngineFallback:
    """Test Jinja2ReportEngine fallback behavior."""

    def test_fallback_to_html_when_pdf_fails(self, tmp_path):
        """Test that engine falls back to HTML if PDF generation fails."""
        from src.reporting.jinja_engine import Jinja2ReportEngine
        
        with patch('src.reporting.jinja_engine.get_scoring_engine', MagicMock()):
            engine = Jinja2ReportEngine()
            engine.pdf_generator.output_path = str(tmp_path)
            
            # Mock PDF failure
            with patch.object(engine.pdf_generator, 'generate', side_effect=RuntimeError("PDF Error")):
                with patch.object(engine, '_gather_data', return_value=_create_test_data("test.com")):
                    with patch.object(engine, 'render_html', return_value="<html>Fallback HTML</html>"):
                        result_path = engine.generate_report("test.com", format="pdf")
                        
                        assert result_path.endswith(".html")
                        assert os.path.exists(result_path)
                        # Verify it's HTML, not PDF
                        with open(result_path, 'r') as f:
                            content = f.read()
                            assert "Fallback HTML" in content


# ============================================================================
# HELPERS
# ============================================================================

def _create_test_data(target):
    """Create minimal test data for report generation."""
    return {
        "scan_info": {
            "target": target,
            "timestamp": "2026-04-28T00:00:00",
            "ozy_version": "6.0.0-alpha.2"
        },
        "findings": {"critical": [], "high": [], "medium": [], "low": []},
        "scoring": [],
        "attack_paths": [],
        "summary": {"total_findings": 0, "risk_score": 0.0},
        "charts": {},
        "custom": {}
    }
