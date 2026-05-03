"""
Jinja2 Report Engine for OzyRecon.

Provides template rendering using Jinja2 with proper loader configuration
to find .j2 templates in resources/reports/ directory.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound

# Import for database access
from src.storage.database import SessionLocal
from src.storage.models import Finding as DBFinding, Scan, Target, Hypothesis
from src.intelligence.scoring_engine import get_scoring_engine
from src.intelligence.logic_analyzer import LogicAnalyzer
from src.discovery.cloud_buckets import cloud_scanner
from src.reporting.schemas import (
    ReportData, ScanInfo, Finding, ScoringItem, AttackPath,
    create_report_data
)
from src.reporting.pdf_generator import PDFGenerator

logger = logging.getLogger(__name__)


class Jinja2ReportEngine:
    """
    Jinja2-based report engine for rendering dynamic HTML reports.

    Configures Jinja2 environment to load templates from
    resources/reports/templates/ directory.
    """

    def __init__(self, template_dir: str = "resources/reports/templates"):
        """
        Initialize the Jinja2 report engine.

        Args:
            template_dir: Path to the directory containing .j2 templates.
                         Can be relative to project root or absolute.
        """
        # Resolve template directory to absolute path
        self.template_dir = self._resolve_path(template_dir)

        # Verify template directory exists
        if not os.path.isdir(self.template_dir):
            raise FileNotFoundError(
                f"Template directory not found: {self.template_dir}"
            )

        # Configure Jinja2 environment with FileSystemLoader
        self.env = Environment(
            loader=FileSystemLoader(searchpath=self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Initialize PDF generator
        self.pdf_generator = PDFGenerator()

    def _resolve_path(self, path: str) -> str:
        """Resolve a path to absolute, handling relative paths from project root."""
        if os.path.isabs(path):
            return path

        # Try to find the path relative to current file's project root
        current_file = Path(__file__)
        project_root = current_file.parent.parent.parent

        resolved = project_root / path
        if resolved.exists():
            return str(resolved)

        # Fallback: use cwd
        return os.path.abspath(path)

    def _add_custom_filters(self):
        """Add custom Jinja2 filters for report rendering (Phase 4)."""
        # Filter 1: datetime - format datetime objects or strings
        def format_datetime(value, format="%B %d, %Y %H:%M:%S"):
            """
            Format datetime objects or strings.

            Args:
                value: datetime object or ISO format string
                format: strftime format string

            Returns:
                Formatted date string or original value if parsing fails
            """
            if value is None:
                return "N/A"

            if isinstance(value, datetime):
                return value.strftime(format)

            if isinstance(value, str):
                try:
                    # Try to parse ISO format
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    return parsed.strftime(format)
                except (ValueError, AttributeError):
                    # Return as-is if can't parse
                    return value

            return str(value)

        self.env.filters['datetime'] = format_datetime

        # Filter 2: severity_sort - sort findings by severity priority
        def severity_sort(findings_dict):
            """
            Sort findings dictionary by severity priority.

            Args:
                findings_dict: Dict with keys 'critical', 'high', 'medium', 'low'

            Returns:
                List of (severity, findings_list) tuples in priority order
            """
            if not findings_dict:
                return []

            severity_order = ['critical', 'high', 'medium', 'low']
            result = []

            for severity in severity_order:
                if severity in findings_dict and findings_dict[severity]:
                    result.append((severity, findings_dict[severity]))

            return result

        self.env.filters['severity_sort'] = severity_sort

        # Filter 3: format_json - pretty print JSON for display
        def format_json(value, indent=2):
            """
            Format a value as pretty-printed JSON.

            Args:
                value: Value to serialize (dict, list, etc.)
                indent: Number of spaces for indentation

            Returns:
                Formatted JSON string
            """
            if value is None:
                return "{}"

            try:
                if isinstance(value, str):
                    # Try to parse string as JSON first
                    try:
                        parsed = json.loads(value)
                        return json.dumps(parsed, indent=indent)
                    except json.JSONDecodeError:
                        # Not valid JSON, return as string
                        return value
                else:
                    return json.dumps(value, indent=indent)
            except (TypeError, ValueError) as e:
                logger.warning(f"Failed to format JSON: {e}")
                return str(value)

        self.env.filters['format_json'] = format_json

    def _gather_data(self, target: str) -> Dict[str, Any]:
        """
        Gather all data needed for report generation from database and engines.

        This method collects:
        - Scan metadata (target, timestamp, duration)
        - Findings grouped by severity (critical, high, medium, low)
        - Top 5 Critical Assets from ScoringEngine
        - Attack paths from LogicAnalyzer (via hypotheses)
        - Summary statistics

        Args:
            target: The target domain or IP to gather data for.

        Returns:
            Dictionary with complete report_data structure (never None).
            Empty structures are returned if no data is found.
        """
        # Initialize with empty structure following schema
        report_data = create_report_data(target)

        db = SessionLocal()
        try:
            # 1. Get target and latest scan metadata
            target_obj = db.query(Target).filter(Target.domain == target).first()
            scan_obj = None
            if target_obj:
                scan_obj = db.query(Scan).filter(
                    Scan.target_id == target_obj.id
                ).order_by(Scan.start_time.desc()).first()

            # Populate scan_info
            if scan_obj:
                start_time = scan_obj.start_time
                end_time = scan_obj.end_time
                duration = None
                if start_time and end_time:
                    duration = (end_time - start_time).total_seconds()

                report_data["scan_info"] = {
                    "target": target,
                    "timestamp": scan_obj.timestamp or datetime.now().strftime("%B %d, %Y %H:%M:%S"),
                    "duration": duration,
                    "ozy_version": "6.0.0-alpha.1",
                }

            # 2. Get findings grouped by severity
            findings_query = db.query(DBFinding).filter(DBFinding.target == target)

            # Initialize findings structure (ensure empty lists, not None)
            findings_by_severity = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            }

            for db_finding in findings_query:
                severity = (db_finding.severity or "low").lower()
                if severity not in findings_by_severity:
                    severity = "low"  # Default to low if unknown severity

                finding_obj = Finding(
                    title=db_finding.name or "Unknown Finding",
                    severity=severity,
                    description=db_finding.description or "",
                    evidence=db_finding.evidence or "",
                    remediation="",  # Not stored in DB model directly
                    cvss_score=db_finding.cvss or 0.0,
                )
                findings_by_severity[severity].append(finding_obj.to_report_context())

            report_data["findings"] = findings_by_severity

            # 3. Get Top 5 from ScoringEngine
            try:
                scoring_engine = get_scoring_engine()
                # Note: ScoringEngine needs scored assets in its cache
                # For now, get what's available
                top_assets = scoring_engine.get_priority_queue(limit=5)

                scoring_list = []
                for asset_score in top_assets:
                    scoring_item = ScoringItem.from_criticality_score(asset_score)
                    scoring_list.append(scoring_item.to_report_context())

                report_data["scoring"] = scoring_list
            except Exception as e:
                logger.warning(f"Failed to get scoring data: {e}")
                report_data["scoring"] = []  # Empty list, not None

            # 4. Get Attack Paths from LogicAnalyzer (via hypotheses)
            try:
                # Get hypotheses from database for this target
                hypotheses = []
                if target_obj:
                    hypotheses = db.query(Hypothesis).filter(
                        Hypothesis.target_id == target_obj.id
                    ).all()

                attack_paths_list = []
                for hyp in hypotheses:
                    # Convert hypothesis to AttackPath
                    hyp_dict = {
                        "id": hyp.id,
                        "type": hyp.type or "Unknown",
                        "confidence": hyp.confidence or 0.0,
                        "description": hyp.description or "",
                        "action": hyp.validation_method or "",
                    }
                    attack_path = AttackPath.from_hypothesis(hyp_dict)
                    attack_paths_list.append(attack_path.to_report_context())

                report_data["attack_paths"] = attack_paths_list
            except Exception as e:
                logger.warning(f"Failed to get attack paths: {e}")
                report_data["attack_paths"] = []  # Empty list, not None

            # 5. Get Cloud Exposure
            try:
                cloud_buckets = cloud_scanner.scan_domain(target)
                report_data["cloud_exposure"] = cloud_buckets
            except Exception as e:
                logger.warning(f"Failed to get cloud data: {e}")
                report_data["cloud_exposure"] = []

            # 6. Calculate summary statistics
            total_findings = sum(len(findings_by_severity[s]) for s in findings_by_severity)

            # Calculate risk score (weighted average)
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
            total_weighted = sum(
                len(findings_by_severity[s]) * severity_weights.get(s, 1)
                for s in findings_by_severity
            )
            risk_score = (total_weighted / total_findings * 10) if total_findings > 0 else 0.0
            risk_score = min(100.0, risk_score)  # Cap at 100

            report_data["summary"] = {
                "total_findings": total_findings,
                "risk_score": round(risk_score, 1),
                "critical_count": len(findings_by_severity["critical"]),
                "high_count": len(findings_by_severity["high"]),
                "medium_count": len(findings_by_severity["medium"]),
                "low_count": len(findings_by_severity["low"]),
            }

            return report_data

        except Exception as e:
            # Log error but return empty structure (never return None)
            logger.error(f"Error gathering data for target {target}: {e}")

            # Return safe empty structure
            return create_report_data(target)
        finally:
            db.close()

    def render_html(
        self,
        report_data: Dict[str, Any],
        template: str = "layouts/report.j2",
    ) -> str:
        """
        Render HTML report from template and data.

        Args:
            report_data: Dictionary containing all report data.
                          Can be a plain dict or a ReportData instance.
            template: Template path relative to template_dir (e.g., 'layouts/report.j2').

        Returns:
            Rendered HTML string.

        Raises:
            FileNotFoundError: If template file is not found.
            ValueError: If report_data is None or invalid.
            RuntimeError: For other template rendering errors.
        """
        # Validate input
        if report_data is None:
            raise ValueError("report_data cannot be None")

        # Convert ReportData to dict if needed
        if hasattr(report_data, 'to_report_context'):
            try:
                report_data = report_data.to_report_context()
            except Exception as e:
                logger.error(f"Failed to convert report_data: {e}")
                raise ValueError(f"Invalid report_data format: {e}")

        # Ensure report_data is a dictionary
        if not isinstance(report_data, dict):
            raise ValueError(f"report_data must be a dict or ReportData instance, got {type(report_data)}")

        # Validate template exists before rendering
        try:
            template_obj = self.env.get_template(template)
        except TemplateNotFound as e:
            raise FileNotFoundError(f"Template not found: {template} in {self.template_dir}") from e
        except Exception as e:
            raise RuntimeError(f"Error loading template '{template}': {e}") from e

        # Prepare context with safe defaults
        context = self._prepare_context(report_data)

        # Render with exception handling
        try:
            rendered = template_obj.render(**context)

            # Post-process: ensure static assets are correctly referenced
            rendered = self._fix_static_references(rendered)

            return rendered

        except Exception as e:
            # Log the error with context for debugging
            logger.error(f"Template rendering failed for '{template}': {e}")
            logger.debug(f"Context keys: {list(context.keys())}")

            # Re-raise with more context
            raise RuntimeError(
                f"Failed to render template '{template}': {e}. "
                f"Check template syntax and context variables."
            ) from e

    def _prepare_context(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare context dictionary with safe defaults for all template variables.

        Args:
            report_data: Raw report data dictionary

        Returns:
            Context dictionary safe for Jinja2 rendering
        """
        # Ensure all required top-level keys exist with safe defaults
        context = {
            "scan_info": report_data.get("scan_info", {}),
            "findings": report_data.get("findings", {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            }),
            "scoring": report_data.get("scoring", []),
            "attack_paths": report_data.get("attack_paths", []),
            "summary": report_data.get("summary", {
                "total_findings": 0,
                "risk_score": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }),
            "charts": report_data.get("charts", {}),
            "custom": report_data.get("custom", {}),
            "cloud_exposure": report_data.get("cloud_exposure", []),
        }

        # Ensure findings structure is correct
        if not isinstance(context["findings"], dict):
            context["findings"] = {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            }
        else:
            # Ensure all severity levels exist
            for severity in ["critical", "high", "medium", "low"]:
                if severity not in context["findings"]:
                    context["findings"][severity] = []

        # Ensure lists are actually lists (not None)
        for key in ["scoring", "attack_paths"]:
            if context[key] is None:
                context[key] = []

        # Ensure summary has all required keys
        if not isinstance(context["summary"], dict):
            context["summary"] = {
                "total_findings": 0,
                "risk_score": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

        return context

    def _fix_static_references(self, html: str) -> str:
        """
        Fix static asset references in rendered HTML.

        Ensures that references to static assets (CSS, JS, images) are correctly
        formatted for both local development and production use.

        Args:
            html: Rendered HTML string

        Returns:
            HTML with corrected static references
        """
        # Fix CSS and JS references to use correct relative paths
        # The base.j2 template has: <link rel="stylesheet" href="static/style.css">
        # We need to ensure the path works when the HTML is opened locally
        
        # Option 1: Make paths absolute from the template directory
        # This assumes the HTML will be in the same directory as the static folder
        
        # For now, we'll ensure the path uses the correct format
        # In production, you might want to use: /static/style.css
        # For local, relative path should work if directory structure is:
        # reports/
        #   ├── output.html (generated report)
        #   └── static/
        #       └── style.css
        
        # We can also inject a <base> tag if needed, but for now just return as-is
        # To add a base tag, uncomment:
        # html = html.replace('<head>', '<head>\n<base href="./">')
        
        return html

    def generate_report(
        self,
        target: str,
        format: str = "html",
        output_dir: Optional[str] = None,
        template: str = "layouts/report.j2",
    ) -> str:
        """
        Generate a report for the given target in the specified format.

        Args:
            target: The target domain or IP.
            format: 'html', 'pdf', or 'both'.
            output_dir: Directory to save the report (defaults to engine settings).
            template: Template to use.

        Returns:
            Path to the primary generated file.
        """
        # Gather data
        report_data = self._gather_data(target)
        
        # Render HTML
        html_content = self.render_html(report_data, template=template)
        
        # Define filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"report_{target}_{timestamp}"
        
        if output_dir:
            self.pdf_generator.output_path = output_dir
            os.makedirs(output_dir, exist_ok=True)
            
        primary_path = ""
        
        if format in ["html", "both"]:
            path = os.path.join(self.pdf_generator.output_path, f"{base_filename}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            primary_path = os.path.abspath(path)
            
        if format in ["pdf", "both"]:
            try:
                pdf_path = self.pdf_generator.save_pdf(html_content, f"{base_filename}.pdf")
                if not primary_path or format == "pdf":
                    primary_path = pdf_path
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
                # Fallback logic
                fallback_path = os.path.join(self.pdf_generator.output_path, f"{base_filename}.html")
                if not os.path.exists(fallback_path):
                    with open(fallback_path, "w", encoding="utf-8") as f:
                        f.write(html_content)
                
                print(f"WARNING: PDF generation failed, HTML report saved as fallback at {fallback_path}")
                if not primary_path or format == "pdf":
                    primary_path = os.path.abspath(fallback_path)
                    
        return primary_path

    def render_charts(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Chart.js configurations or static fallbacks.

        Phase 4 implementation: Creates default charts based on findings data.

        Args:
            report_data: Dictionary containing report data.

        Returns:
            Dictionary with chart configurations.
        """
        charts = {}

        # Only generate charts if we have findings
        findings = report_data.get("findings", {})
        summary = report_data.get("summary", {})

        if not findings or not summary:
            return charts

        # Chart 1: Severity Doughnut Chart
        severity_labels = ["Critical", "High", "Medium", "Low"]
        severity_data = [
            summary.get("critical_count", 0),
            summary.get("high_count", 0),
            summary.get("medium_count", 0),
            summary.get("low_count", 0),
        ]

        # Only add chart if there are findings
        if sum(severity_data) > 0:
            charts["severityChart"] = {
                "chart_type": "doughnut",
                "labels": severity_labels,
                "datasets": [{
                    "data": severity_data,
                    "backgroundColor": ["#dc2626", "#ea580c", "#d97706", "#2563eb"],
                    "borderWidth": 1,
                }],
                "options": {
                    "responsive": True,
                    "plugins": {
                        "legend": {"position": "bottom"},
                    },
                },
            }

        # Chart 2: Risk Score Gauge (as bar chart)
        risk_score = summary.get("risk_score", 0)
        charts["riskGauge"] = {
            "chart_type": "bar",
            "labels": ["Risk Score"],
            "datasets": [{
                "label": "Risk Score (0-100)",
                "data": [risk_score],
                "backgroundColor": ["#dc2626" if risk_score >= 80 else "#ea580c" if risk_score >= 60 else "#d97706" if risk_score >= 40 else "#2563eb"],
                "borderWidth": 1,
            }],
            "options": {
                "indexAxis": "y",
                "scales": {
                    "x": {"max": 100, "min": 0},
                },
            },
        }

        return charts
