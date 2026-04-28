"""
Report Data Schemas for OzyRecon.

Defines the structure of report_data dictionary used by
Jinja2ReportEngine and PDFGenerator.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScanInfo:
    """Metadata about the scan."""

    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: Optional[float] = None  # in seconds
    ozy_version: str = "6.0.0-alpha.1"

    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert to dictionary suitable for Jinja2 templates.
        
        Returns:
            Dictionary with all fields, excluding None values.
        """
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "ozy_version": self.ozy_version,
        }


@dataclass
class Finding:
    """A single finding from the scan."""

    title: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Jinja2 templates.
        
        Returns:
            Dictionary with all fields, None values become empty strings.
        """
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence or "",
            "remediation": self.remediation or "",
            "cvss_score": self.cvss_score or 0.0,
        }


@dataclass
class ScoringItem:
    """An item from the scoring/priority queue (Top 5 Critical Assets)."""

    asset: str
    criticality_index: float
    port: Optional[int] = None
    service: Optional[str] = None
    reasoning: Optional[str] = None

    @classmethod
    def from_criticality_score(cls, score: Any) -> "ScoringItem":
        """
        Create ScoringItem from ScoringEngine's CriticalityScore.
        
        Args:
            score: CriticalityScore object from ScoringEngine.
            
        Returns:
            ScoringItem instance.
        """
        return cls(
            asset=score.asset_identifier or score.service_type,
            criticality_index=float(score.index),
            port=None,  # Not available in CriticalityScore directly
            service=score.service_type,
            reasoning=f"Base: {score.base_score}, Modifiers: {len(score.modifiers)} applied",
        )
    
    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Jinja2 templates.
        
        Returns:
            Dictionary with all fields, None becomes empty string/0.
        """
        return {
            "asset": self.asset,
            "criticality_index": self.criticality_index,
            "port": self.port or 0,
            "service": self.service or "",
            "reasoning": self.reasoning or "",
        }


@dataclass
class AttackPath:
    """An attack path from the logic analyzer."""

    path_id: str
    description: str
    steps: List[str]
    risk_score: Optional[float] = None
    prerequisites: List[str] = field(default_factory=list)

    @classmethod
    def from_hypothesis(cls, hypothesis: Dict[str, Any]) -> "AttackPath":
        """
        Create AttackPath from LogicAnalyzer hypothesis dict.
        
        Args:
            hypothesis: Dict with keys like 'id', 'type', 'confidence', 'description', 'action'
            
        Returns:
            AttackPath instance.
        """
        # Generate steps from the hypothesis - simplified for now
        steps = [
            f"Detected pattern: {hypothesis.get('type', 'Unknown')}",
            hypothesis.get('description', ''),
            hypothesis.get('action', ''),
        ]
        
        return cls(
            path_id=hypothesis.get('id', 'UNKNOWN'),
            description=hypothesis.get('description', ''),
            steps=[s for s in steps if s],  # Remove empty steps
            risk_score=float(hypothesis.get('confidence', 0.0)) * 100,  # Convert to 0-100 scale
            prerequisites=[],  # LogicAnalyzer doesn't provide prerequisites yet
        )
    
    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Jinja2 templates.
        
        Returns:
            Dictionary with all fields, None becomes empty strings/lists.
        """
        return {
            "path_id": self.path_id,
            "description": self.description,
            "steps": self.steps if self.steps else [],
            "risk_score": self.risk_score or 0.0,
            "prerequisites": self.prerequisites if self.prerequisites else [],
        }


@dataclass
class ChartConfig:
    """Configuration for Chart.js charts."""

    chart_type: str  # "bar", "pie", "line", etc.
    labels: List[str]
    datasets: List[Dict[str, Any]]
    options: Dict[str, Any] = field(default_factory=dict)

    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Jinja2 templates.
        
        Returns:
            Dictionary with all fields.
        """
        return {
            "chart_type": self.chart_type,
            "labels": self.labels if self.labels else [],
            "datasets": self.datasets if self.datasets else [],
            "options": self.options if self.options else {},
        }


@dataclass
class ReportData:
    """
    Complete report data structure.

    This is the main data structure passed to Jinja2 templates.
    """

    # Scan metadata
    scan_info: ScanInfo

    # Findings grouped by severity
    findings: Dict[str, List[Finding]] = field(
        default_factory=lambda: {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
    )

    # Top 5 Critical Assets from ScoringEngine
    scoring: List[ScoringItem] = field(default_factory=list)

    # Attack paths from LogicAnalyzer
    attack_paths: List[AttackPath] = field(default_factory=list)

    # Summary statistics
    summary: Dict[str, Any] = field(
        default_factory=lambda: {
            "total_findings": 0,
            "risk_score": 0.0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }
    )

    # Chart configurations (optional, for Chart.js)
    charts: Dict[str, ChartConfig] = field(default_factory=dict)

    # Any additional custom data
    custom: Dict[str, Any] = field(default_factory=dict)

    def to_report_context(self) -> Dict[str, Any]:
        """
        Convert entire ReportData to a flat dictionary for Jinja2 templates.
        
        This method recursively converts all nested dataclasses to dictionaries,
        ensuring empty lists/dicts instead of None for template safety.
        
        Returns:
            Flat dictionary with all report data, safe for Jinja2 rendering.
        """
        # Convert scan_info using its to_report_context method
        scan_info_dict = self.scan_info.to_report_context() if hasattr(self.scan_info, 'to_report_context') else {
            "target": self.scan_info.target if self.scan_info else "",
            "timestamp": "",
            "duration": None,
            "ozy_version": "6.0.0-alpha.1",
        }
        
        # Convert findings (grouped by severity) - ensure no None values
        findings_dict = {}
        for severity, finding_list in self.findings.items():
            if finding_list:
                findings_dict[severity] = [
                    f.to_report_context() if hasattr(f, 'to_report_context') else {
                        "title": f.title if hasattr(f, 'title') else "",
                        "severity": severity,
                        "description": "",
                        "evidence": "",
                        "remediation": "",
                        "cvss_score": 0.0,
                    }
                    for f in finding_list
                ]
            else:
                findings_dict[severity] = []  # Empty list, not None
        
        # Convert scoring items
        scoring_list = []
        if self.scoring:
            for item in self.scoring:
                if hasattr(item, 'to_report_context'):
                    scoring_list.append(item.to_report_context())
                else:
                    scoring_list.append({
                        "asset": getattr(item, 'asset', ''),
                        "criticality_index": getattr(item, 'criticality_index', 0.0),
                        "port": getattr(item, 'port', 0),
                        "service": getattr(item, 'service', ''),
                        "reasoning": getattr(item, 'reasoning', ''),
                    })
        
        # Convert attack paths
        attack_paths_list = []
        if self.attack_paths:
            for path in self.attack_paths:
                if hasattr(path, 'to_report_context'):
                    attack_paths_list.append(path.to_report_context())
                else:
                    attack_paths_list.append({
                        "path_id": getattr(path, 'path_id', ''),
                        "description": getattr(path, 'description', ''),
                        "steps": getattr(path, 'steps', []),
                        "risk_score": getattr(path, 'risk_score', 0.0),
                        "prerequisites": getattr(path, 'prerequisites', []),
                    })
        
        # Convert charts
        charts_dict = {}
        if self.charts:
            for chart_name, chart_config in self.charts.items():
                if hasattr(chart_config, 'to_report_context'):
                    charts_dict[chart_name] = chart_config.to_report_context()
                else:
                    charts_dict[chart_name] = {
                        "chart_type": getattr(chart_config, 'chart_type', 'bar'),
                        "labels": getattr(chart_config, 'labels', []),
                        "datasets": getattr(chart_config, 'datasets', []),
                        "options": getattr(chart_config, 'options', {}),
                    }
        
        # Build final context
        return {
            "scan_info": scan_info_dict,
            "findings": findings_dict if findings_dict else {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
            },
            "scoring": scoring_list,
            "attack_paths": attack_paths_list,
            "summary": self.summary if self.summary else {
                "total_findings": 0,
                "risk_score": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            },
            "charts": charts_dict,
            "custom": self.custom if self.custom else {},
        }


def create_report_data(target: str, **kwargs) -> Dict[str, Any]:
    """
    Create a report_data dictionary with proper structure.

    This is a helper function that creates a dictionary suitable for
    passing to Jinja2ReportEngine.render_html().

    Args:
        target: The scan target.
        **kwargs: Additional data to include.

    Returns:
        Dictionary with all report data.
    """
    # Build the report data dict
    report_data = {
        "scan_info": {
            "target": target,
            "timestamp": datetime.now().strftime("%B %d, %Y %H:%M:%S"),
            "ozy_version": "6.0.0-alpha.1",
        },
        "findings": {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        },
        "scoring": [],
        "attack_paths": [],
        "summary": {
            "total_findings": 0,
            "risk_score": 0.0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        },
        "charts": {},
        "custom": {},
    }

    # Update with any provided kwargs
    report_data.update(kwargs)

    return report_data
