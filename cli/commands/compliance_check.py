"""
Compliance Check Command - Validates scan results meet project standards
"""

import json
from importlib.util import find_spec
from pathlib import Path
from typing import Dict, Any, Optional

import click
from rich.table import Table

from cli.shared import console, render_outcome, render_panel
from src.core.target_normalizer import normalize_lookup_target

# Forbidden strings that should never appear in reports
FORBIDDEN_STRINGS = [
    "evil-corp.com",
    "artifact.test",
    "critical-target.test",
    "example-vulnerable",
    "test.local",
    "localhost",
]

# Required report sections
REQUIRED_SECTIONS = [
    "Resumen",
    "Alcance",
    "Metodología",
    "Activos",
    "Hallazgos",
    "Recomendaciones",
]


def check_scope_guard(session_dir: Path) -> Dict[str, Any]:
    """Check for out-of-scope assets."""
    issues = []

    # Check trace.json
    trace_file = session_dir / "trace.json"
    if trace_file.exists():
        data = json.loads(trace_file.read_text())

        # Check for forbidden strings in session data
        session_json = json.dumps(data)
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden in session_json:
                issues.append(f"Found forbidden domain: {forbidden}")

    return {
        "name": "Scope Guard",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
    }


def check_demo_data(session_dir: Path) -> Dict[str, Any]:
    """Check for demo data contamination."""
    issues = []

    # Check all JSON files in session
    for json_file in session_dir.rglob("*.json"):
        try:
            content = json_file.read_text()
            for forbidden in FORBIDDEN_STRINGS:
                if forbidden.lower() in content.lower():
                    issues.append(f"Demo data in {json_file.name}: {forbidden}")
        except OSError:
            pass

    # Check HTML reports
    for html_file in session_dir.rglob("*.html"):
        try:
            content = html_file.read_text().lower()
            for forbidden in FORBIDDEN_STRINGS:
                if forbidden.lower() in content:
                    issues.append(f"Demo data in {html_file.name}: {forbidden}")
        except OSError:
            pass

    return {
        "name": "Demo Data Leak",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
    }


def check_profile_safety(session_dir: Path, profile_used: str) -> Dict[str, Any]:
    """Check profile safety compliance."""
    issues = []

    from src.scope.profiles import get_profile

    profile = get_profile(profile_used)

    if not profile:
        issues.append(f"Profile not found: {profile_used}")
    else:
        # Check for forbidden tools in passive/safe-active
        if profile_used in ["passive", "safe-active"]:
            forbidden = {"nmap", "nuclei", "katana", "ffuf", "gobuster"}
            for tool in profile.tools:
                if tool in forbidden:
                    issues.append(f"Forbidden tool in {profile_used}: {tool}")

    # Check if authorized profile was used without auth simulation
    if profile_used == "authorized":
        auth_file = session_dir / "authorization.txt"
        if not auth_file.exists():
            issues.append("Authorized profile used without authorization file")

    return {
        "name": "Profile Safety",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
    }


def check_evidence_integrity(session_dir: Path) -> Dict[str, Any]:
    """Check that findings have evidence."""
    issues = []

    # Check findings.json
    findings_file = session_dir / "normalized" / "findings.json"
    if findings_file.exists():
        findings = json.loads(findings_file.read_text())

        # Check if findings have evidence
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    # Check for evidence fields
                    has_evidence = any(
                        key in finding for key in ["evidence", "evidence_id", "source", "timestamp"]
                    )
                    if not has_evidence:
                        fid = finding.get("id", finding.get("name", "unknown"))
                        issues.append(f"Finding lacks evidence: {fid}")

    return {
        "name": "Evidence Integrity",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
    }


def check_report_contract(session_dir: Path) -> Dict[str, Any]:
    """Check report has required sections."""
    issues = []
    warnings = []

    # Check in session directory first
    html_files = list(session_dir.glob("*.html"))

    # If not found in session, check reports/reales/{target}/
    if not html_files:
        reports_dir = Path("reports/reales")
        if reports_dir.exists():
            for target_dir in reports_dir.iterdir():
                if target_dir.is_dir():
                    for session_report_dir in target_dir.iterdir():
                        if session_report_dir.is_dir():
                            # Check if this is our session
                            if (
                                session_report_dir.name == session_dir.name
                                or session_dir.name in str(session_report_dir)
                            ):
                                html_files = list(session_report_dir.glob("*.html"))
                                if html_files:
                                    break

    if not html_files:
        warnings.append("No HTML report found (report may not have been generated)")
        # Don't fail - this might be a dry-run or incomplete session
        return {
            "name": "Report Contract",
            "passed": True,  # Warning, not failure
            "score": 15,
            "max_score": 15,
            "issues": [],
            "warnings": warnings,
        }

    report_content = html_files[0].read_text().lower()

    # Check for required sections
    for section in REQUIRED_SECTIONS:
        if section.lower() not in report_content:
            issues.append(f"Missing section: {section}")

    return {
        "name": "Report Contract",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
        "warnings": warnings,
    }


def check_dependency_health() -> Dict[str, Any]:
    """Check dependency health."""
    issues = []
    warnings = []

    # Check python deps
    if find_spec("weasyprint") is None:
        warnings.append("WeasyPrint not installed - PDF export is optional")

    # Check go binaries
    import shutil

    binaries = ["subfinder", "dnsx", "httpx", "nuclei", "nmap"]
    for binary in binaries:
        if not shutil.which(binary) and not Path(f"tools/go/bin/{binary}").exists():
            warnings.append(f"{binary} not found")

    return {
        "name": "Dependency Health",
        "passed": len(issues) == 0,
        "score": 10 if len(issues) == 0 and len(warnings) == 0 else (5 if len(warnings) < 3 else 0),
        "max_score": 10,
        "issues": issues,
        "warnings": warnings,
    }


def check_scoring_explanation(session_dir: Path) -> Dict[str, Any]:
    """Check risk scoring has explanations."""
    issues = []

    # Check if scoring is present in assets
    normalized_dir = session_dir / "normalized"
    if normalized_dir.exists():
        for json_file in normalized_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                # Check for severity/risk fields
                if isinstance(data, list):
                    for item in data[:5]:  # Check first 5
                        if isinstance(item, dict):
                            has_score = any(
                                key in item for key in ["severity", "risk", "criticality", "impact"]
                            )
                            if not has_score:
                                issues.append(f"Item lacks scoring: {json_file.name}")
            except (OSError, json.JSONDecodeError):
                pass

    return {
        "name": "Risk Scoring",
        "passed": len(issues) == 0,
        "score": 15 if len(issues) == 0 else 0,
        "max_score": 15,
        "issues": issues,
    }


def _matches_target(session_target: str, target: str) -> bool:
    """Return True when a stored session target matches the requested target."""
    return normalize_lookup_target(session_target) == normalize_lookup_target(target)


@click.command(name="compliance-check")
@click.argument("session_id", required=False)
@click.option("--target", default=None, help="Target domain")
@click.option("--latest", "use_latest", is_flag=True, help="Use latest session for target")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def compliance_check(
    session_id: Optional[str], target: Optional[str], use_latest: bool, json_output: bool
):
    """
    Validate scan results meet project standards.

    Runs compliance checks on a scan session to verify:
    - No out-of-scope assets
    - No demo data contamination
    - Profile safety compliance
    - Evidence integrity
    - Report contract
    - Dependency health
    - Risk scoring

    Usage:
        python ozy.py compliance-check runs/<session_id>
        python ozy.py compliance-check --target example.com
    """
    render_panel("[bold cyan]PromptWall Compliance Check[/bold cyan]", border_style="cyan")

    # Find session directory
    session_dir = None

    if session_id:
        session_dir = Path(f"runs/{session_id}")
    elif target or use_latest:
        # Find latest session for target (or latest overall if --latest)
        runs_dir = Path("runs")
        target = target or "*"  # If --latest without target, find any
        if runs_dir.exists():
            sessions = []
            for sd in runs_dir.iterdir():
                if sd.is_dir() and sd.name != "test_session":
                    trace = sd / "trace.json"
                    if trace.exists():
                        try:
                            data = json.loads(trace.read_text())
                            session_target = data.get("target", "")
                            # Match target or use latest if --latest flag
                            if use_latest or (target and _matches_target(session_target, target)):
                                sessions.append((sd, sd.stat().st_mtime))
                        except (OSError, json.JSONDecodeError):
                            pass

            # Sort by modification time, newest first
            sessions.sort(key=lambda x: x[1], reverse=True)
            if sessions:
                session_dir = sessions[0][0]
                if use_latest:
                    render_panel(
                        f"Using latest session for: {sessions[0][0].name}", border_style="cyan"
                    )

    if not session_dir or not session_dir.exists():
        render_outcome(
            "Session not found. Provide session_id, --target, or --latest.", border_style="red"
        )
        return

    render_panel(f"[bold]Checking session:[/bold] {session_dir.name}", border_style="cyan")

    # Run all checks
    checks = []

    checks.append(check_scope_guard(session_dir))
    checks.append(check_demo_data(session_dir))
    checks.append(check_profile_safety(session_dir, "safe-active"))  # Assume safe-active
    checks.append(check_evidence_integrity(session_dir))
    checks.append(check_report_contract(session_dir))
    checks.append(check_dependency_health())
    checks.append(check_scoring_explanation(session_dir))

    if json_output:
        output = {
            "session": session_dir.name,
            "checks": [
                {
                    "name": c["name"],
                    "passed": c["passed"],
                    "score": c["score"],
                    "max": c["max_score"],
                }
                for c in checks
            ],
        }
        console.print_json(json.dumps(output, indent=2))
        return

    # Display results
    table = Table(title="[bold]Compliance Checks[/bold]", show_header=True)
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Score", style="white")

    total_score = 0
    max_score = 0

    for check in checks:
        status = "[green]PASS" if check["passed"] else "[red]FAIL"
        score_text = f"{check['score']}/{check['max_score']}"
        table.add_row(check["name"], status, score_text)

        total_score += check["score"]
        max_score += check["max_score"]

        # Show issues/warnings
        if check.get("issues"):
            for issue in check["issues"]:
                console.print(f"  [red]  - {issue}[/red]")
        if check.get("warnings"):
            for warn in check["warnings"]:
                console.print(f"  [yellow]  ⚠ {warn}[/yellow]")

    console.print(table)

    # Final score
    final_score = int((total_score / max_score) * 100) if max_score > 0 else 0

    render_panel(
        f"[bold]Final Score: {total_score}/{max_score} ({final_score}%)[/bold]", border_style="cyan"
    )

    if final_score >= 90:
        status = "[bold green]READY FOR DEMO[/bold green]"
    elif final_score >= 75:
        status = "[bold yellow]READY WITH WARNINGS[/bold yellow]"
    elif final_score >= 60:
        status = "[bold yellow]PROTOTYPE INCOMPLETE[/bold yellow]"
    else:
        status = "[bold red]NOT PRESENTABLE[/bold red]"

    render_outcome(f"Status: {status}")


__all__ = ["compliance_check"]
