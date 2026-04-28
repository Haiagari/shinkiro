"""
PDF Generator for OzyRecon using WeasyPrint.

Handles HTML to PDF conversion with proper static file serving
(CSS, images) for WeasyPrint rendering.
"""

import os
import warnings
from pathlib import Path
from typing import Optional, Dict, Any


class PDFGenerator:
    """
    PDF generator using WeasyPrint with custom URL fetcher for static files.

    Configures WeasyPrint to correctly resolve static files (CSS, images)
    from the resources/reports/static/ directory.
    """

    def __init__(self, output_path: str = "reports"):
        """
        Initialize the PDF generator.

        Args:
            output_path: Directory where PDF files will be saved.
                         Will be created if it doesn't exist.
        """
        self.output_path = output_path
        os.makedirs(output_path, exist_ok=True)

        # Base directory for static files (CSS, images)
        self.static_dir = self._resolve_static_dir()
        self.template_dir = self._resolve_template_dir()

        # WeasyPrint is optional - check if it's available
        self.weasyprint_available = self._check_weasyprint()

    def _resolve_static_dir(self) -> str:
        """Resolve the static files directory path."""
        # Try relative to project root
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent
        static_path = project_root / "resources" / "reports" / "static"

        if static_path.exists():
            return str(static_path)

        # Fallback: relative to cwd
        return os.path.abspath("resources/reports/static")

    def _resolve_template_dir(self) -> str:
        """Resolve the templates directory path."""
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent
        template_path = project_root / "resources" / "reports" / "templates"

        if template_path.exists():
            return str(template_path)

        return os.path.abspath("resources/reports/templates")

    def _check_weasyprint(self) -> bool:
        """Check if WeasyPrint is available."""
        try:
            import weasyprint  # noqa: F401
            from weasyprint.urls import URLFetchingError  # noqa: F401

            return True
        except (ImportError, Exception) as e:
            # Check for system dependencies issues (e.g. libcairo)
            warnings.warn(
                f"WeasyPrint or its dependencies not properly installed: {e}. "
                "PDF generation will not be available. "
                "Install with: pip install weasyprint and check system libs (libcairo, libpango).",
                UserWarning,
                stacklevel=2,
            )
            return False

    def _custom_url_fetcher(self, url: str, *args, **kwargs) -> Dict[str, Any]:
        """
        Custom URL fetcher for WeasyPrint to resolve static files correctly.

        This function allows WeasyPrint to find CSS and image files
        referenced in HTML with relative or absolute URLs.

        Args:
            url: The URL to fetch (file:// or http://).

        Returns:
            Dictionary with 'string' (content) and 'mime_type'.

        Raises:
            ValueError: If URL cannot be resolved.
        """
        from weasyprint.urls import URLFetchingError

        # Handle file:// URLs pointing to static files
        if url.startswith("file://"):
            # Extract path from file:// URL
            file_path = url[7:]  # Remove 'file://' prefix

            # Check if it's a relative path to static dir
            if not os.path.isabs(file_path):
                # Try static dir first
                full_path = os.path.join(self.static_dir, file_path)
                if os.path.exists(full_path):
                    return self._read_file(full_path)

                # Try template dir (for relative paths in templates)
                full_path = os.path.join(self.template_dir, file_path)
                if os.path.exists(full_path):
                    return self._read_file(full_path)
            else:
                # Absolute path - use directly
                if os.path.exists(file_path):
                    return self._read_file(file_path)

        # Handle relative URLs without scheme (e.g., "style.css" or "static/style.css")
        if not url.startswith(("http://", "https://", "file://")):
            # Try in static dir
            full_path = os.path.join(self.static_dir, url)
            if os.path.exists(full_path):
                return self._read_file(full_path)

            # Try in template dir
            full_path = os.path.join(self.template_dir, url)
            if os.path.exists(full_path):
                return self._read_file(full_path)

        # If we can't handle it, let WeasyPrint try (will likely fail for local files)
        raise URLFetchingError(f"Cannot resolve URL: {url}")

    def _read_file(self, path: str) -> Dict[str, Any]:
        """Read a file and return it in WeasyPrint's expected format."""
        import mimetypes

        mime_type, _ = mimetypes.guess_type(path)
        if mime_type is None:
            # Default MIME types for common files
            if path.endswith(".css"):
                mime_type = "text/css"
            elif path.endswith(".js"):
                mime_type = "application/javascript"
            elif path.endswith(".html"):
                mime_type = "text/html"
            else:
                mime_type = "application/octet-stream"

        with open(path, "rb") as f:
            content = f.read()

        return {"string": content, "mime_type": mime_type}

    def generate(
        self,
        html_content: str,
        output_filename: str = "report.pdf",
        base_url: Optional[str] = None,
    ) -> str:
        """
        Generate PDF from HTML content using WeasyPrint.

        Args:
            html_content: HTML string to convert to PDF.
            output_filename: Name of the output PDF file.
            base_url: Base URL for resolving relative URLs in HTML.
                      If None, uses file:// URL to template dir.

        Returns:
            Absolute path to the generated PDF file.

        Raises:
            RuntimeError: If WeasyPrint is not available or generation fails.
        """
        if not self.weasyprint_available:
            raise RuntimeError(
                "WeasyPrint is not installed. Cannot generate PDF. "
                "Install with: pip install weasyprint"
            )

        import weasyprint

        # Set base_url for resolving relative URLs (CSS, images)
        if base_url is None:
            base_url = f"file://{self.template_dir}/"

        # Configure WeasyPrint with custom URL fetcher
        # This ensures static files are found correctly
        try:
            html = weasyprint.HTML(
                string=html_content,
                base_url=base_url,
                url_fetcher=self._custom_url_fetcher,
            )

            output_path = os.path.join(self.output_path, output_filename)
            html.write_pdf(output_path)

            # Validate the output
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                raise RuntimeError(
                    f"PDF generation failed: output file is empty or missing: {output_path}"
                )

            return os.path.abspath(output_path)

        except Exception as e:
            # Fallback: save HTML if PDF fails (implemented in Phase5)
            raise RuntimeError(f"PDF generation failed: {e}") from e

    def save_pdf(self, html_content: str, output_filename: str) -> str:
        """
        Generate and persist the PDF file.
        This method acts as the primary interface for PDF generation.

        Args:
            html_content: The rendered HTML content.
            output_filename: Desired PDF filename.

        Returns:
            Absolute path to the generated PDF.
        """
        return self.generate(html_content, output_filename)

        """
        Fallback: save HTML when PDF generation fails.

        Args:
            html_content: HTML string to save.
            output_filename: Name of the output HTML file.

        Returns:
            Absolute path to the saved HTML file.
        """
        output_path = os.path.join(self.output_path, output_filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return os.path.abspath(output_path)
