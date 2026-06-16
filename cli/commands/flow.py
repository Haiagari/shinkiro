"""
CLI Command: flow - end-to-end OzyRecon launcher.

Runs verify -> hunt -> local analysis -> report and stores the outputs in the
repo-local real reports folder.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import click
import yaml

from cli.shared import (
    console,
    ensure_config_loaded,
    handle_exception,
    render_plan,
    render_stage,
    render_outcome,
    render_timing_summary,
)
from cli.commands.verify import (
    check_api_contract,
    check_binaries,
    check_folders,
    check_intelligence_engines,
    check_python_version,
)

# Reporting module removed - using JSON/Markdown output only
from src.scope import host_in_allowed_domains
from src.scope.profiles import get_profile
from src.storage.database import SessionLocal
from src.storage.models import Scan, Subdomain, Target
from src.storage.queries import DBQueries
from src.storage.diff import DiffEngine
from src.core.target_normalizer import normalize_lookup_target
from src.core.tool_manager import tool_manager
from src.plugins.hooks import dispatch_hook

# OzyRecon v1.2: Hexagonal Architecture Components
from src.application.use_cases.orchestrator_v10 import OzyOrchestratorV10
from src.application.ports.event_bus import InMemoryEventBus
from src.domain.services.evidence_service import EvidenceService
from src.adapters.storage.sqlite_repository import SQLiteAssetRepository
from src.adapters.tools.nmap_adapter import NmapAdapter
from src.adapters.registry.ozy_registry_adapter import OzyRegistryAdapter
from src.adapters.policy.ozy_policy_adapter import OzyPolicyAdapter
from src.utils.crypto import evidence_signer


def _safe_segment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned or "target"


def _flow_plan(target: str, scan_profile: str, dry_run: bool, allow_degraded: bool) -> None:
    plan_lines = [
        f"[bold]Target:[/bold] {target}",
        f"[bold]Profile:[/bold] {scan_profile}",
        f"[bold]Mode:[/bold] {'dry-run' if dry_run else 'live'}",
        f"[bold]Verification:[/bold] {'allow degraded' if allow_degraded else 'strict'}",
        "",
        "[bold]Pipeline:[/bold]",
        "  1. Preflight verification",
        "  2. Scope and authorization gate",
        "  3. Adaptive hunt execution",
        "  4. Analysis snapshot",
        "  5. Diff comparison and final summary",
    ]
    render_plan("OzyRecon Flow", plan_lines)


def _flow_context(
    target: str,
    threads: Optional[int],
    speed: str,
    depth_level: int,
    intent: str,
    steroids: bool,
    ghost: bool,
) -> None:
    context_lines = [
        f"[bold]Target:[/bold] {target}",
        f"[bold]Threads:[/bold] {threads or 'auto'}",
        f"[bold]Speed:[/bold] {speed}",
        f"[bold]Depth:[/bold] {depth_level}",
        f"[bold]Intent:[/bold] {intent}",
        f"[bold]Steroids:[/bold] {'enabled' if steroids else 'disabled'}",
        f"[bold]Ghost mode:[/bold] {'enabled' if ghost else 'disabled'}",
    ]
    render_plan("Execution Context", context_lines, border_style="cyan")


def _render_flow_results(summary: Dict[str, Any], target: str) -> None:
    artifacts = summary.get("artifacts", {})
    analysis = summary.get("analysis", {})
    result_lines = [
        f"[bold]Session:[/bold] {summary.get('session_id')}",
        f"[bold]Status:[/bold] {summary.get('status')}",
        f"[bold]Session folder:[/bold] {summary.get('session_dir') or '-'}",
        f"[bold]Report:[/bold] {artifacts.get('report') or '-'}",
        f"[bold]Report status:[/bold] {'ready' if artifacts.get('report') else 'warning'}",
        f"[bold]Analysis:[/bold] {artifacts.get('analysis_md') or '-'}",
        f"[bold]Live subdomains:[/bold] {len(analysis.get('live_subdomains', []))}",
        f"[bold]Open ports:[/bold] {len(analysis.get('open_ports', []))}",
        f"[bold]Target:[/bold] {target}",
    ]
    render_plan("Flow Results", result_lines, border_style="green")


def _build_data_summary_lines(summary: Dict[str, Any]) -> list[str]:
    analysis = summary.get("analysis", {})
    live_subdomains = analysis.get("live_subdomains", [])
    open_ports = analysis.get("open_ports", [])
    recommendations = analysis.get("recommendations", [])

    critical_ports = [p for p in open_ports if p.get("port") in {21, 22, 3306, 2083, 2096}]
    top_hosts = [host for host in live_subdomains if host != summary.get("target")][:5]

    lines = [
        f"[bold]Live hosts:[/bold] {len(live_subdomains)}",
        f"[bold]Open ports:[/bold] {len(open_ports)}",
        f"[bold]Critical services:[/bold] {', '.join(str(p.get('port')) for p in critical_ports) or 'none'}",
        f"[bold]High-value hosts:[/bold] {', '.join(top_hosts) or 'none'}",
        f"[bold]Recommendations:[/bold] {len(recommendations)}",
    ]
    return lines


def _render_data_summary(summary: Dict[str, Any]) -> None:
    render_plan("Data Summary", _build_data_summary_lines(summary), border_style="yellow")


def _collect_verification(allow_degraded: bool) -> Dict[str, Any]:
    checks = [
        ("Python version", check_python_version()),
        ("Required folders", check_folders()),
        ("Required tools", check_binaries()),
        ("Intelligence engines", check_intelligence_engines()),
        ("API contract", check_api_contract()),
    ]
    passed = all(ok for _, ok in checks)
    return {
        "allow_degraded": allow_degraded,
        "passed": passed,
        "checks": [{"name": name, "ok": ok} for name, ok in checks],
    }


def _run_hunt(target: str, session_id: str, **options: Any) -> Dict[str, Any]:
    # OzyRecon v1.2 Wiring: Dependency Injection
    # ---------------------------------------------------------
    event_bus = InMemoryEventBus()
    # If a platform URL is configured in env, we could add the WebhookEventAdapter here

    asset_repo = SQLiteAssetRepository()
    tool_provider = NmapAdapter()
    registry_client = OzyRegistryAdapter()
    policy_engine = OzyPolicyAdapter()
    evidence_svc = EvidenceService(signer=evidence_signer)

    v12_orchestrator = OzyOrchestratorV10(
        asset_repository=asset_repo,
        tool_provider=tool_provider,
        event_bus=event_bus,
        registry_client=registry_client,
        policy_engine=policy_engine,
        evidence_service=evidence_svc,
    )

    # Execute the new engine
    # In v1.2, we keep legacy parameters compatibility by mapping them if needed,
    # but the core execution is now governed by v10 logic.
    v12_orchestrator.execute_recon(target)

    return {"status": "completed", "session_id": session_id}


def _build_analysis_snapshot(
    target: str,
    session_id: str,
    analyze_host: Optional[str] = None,
) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        lookup_target = normalize_lookup_target(target)
        scan = db.query(Scan).filter(Scan.session_id == session_id).first()
        target_obj = db.query(Target).filter(Target.domain == lookup_target).first()
        if not scan:
            return {
                "status": "missing_scan",
                "target": target,
                "session_id": session_id,
                "analysis": "No scan row was found for this session.",
                "recommendations": [],
            }

        live_subdomains = [s for s in scan.subdomains if s.is_live]
        open_ports = [p for p in scan.ports if getattr(p, "state", "open") == "open"]
        selected_host = normalize_lookup_target(analyze_host or target)

        host_target = db.query(Subdomain).filter(Subdomain.domain == selected_host).first()
        if not host_target and selected_host != lookup_target:
            selected_host = lookup_target
            host_target = db.query(Subdomain).filter(Subdomain.domain == selected_host).first()

        technologies = []
        semantic_labels = []
        business_impact = "LOW"
        title = selected_host
        if host_target:
            technologies = host_target.technologies or []
            semantic_labels = host_target.semantic_labels or []
            business_impact = host_target.business_impact or "LOW"
            title = host_target.title or selected_host
        elif target_obj:
            technologies = target_obj.technologies or []

        critical_ports = [p for p in open_ports if p.port in {21, 22, 3306, 2083, 2096}]
        high_value_hosts = [s.domain for s in live_subdomains if s.domain != lookup_target][:5]

        analysis = (
            f"Target {target} has {len(live_subdomains)} live subdomains and "
            f"{len(open_ports)} open ports in session {session_id}. "
            f"Critical services observed: {', '.join(str(p.port) for p in critical_ports) or 'none'}."
        )
        if high_value_hosts:
            analysis += f" High-value hosts include {', '.join(high_value_hosts)}."

        recommendations = [
            "Restrict administrative services to trusted IPs or VPN.",
            "Move MySQL behind a firewall or localhost-only binding.",
            "Enable WAF and rate limiting on the public web surface.",
        ]
        if any(
            "moodle" in (lab or "").lower() for lab in semantic_labels
        ) or selected_host.startswith("aula."):
            recommendations.append("Fix Moodle permissions and cache directory ownership.")

        snapshot = {
            "status": "generated",
            "target": target,
            "session_id": session_id,
            "selected_host": selected_host,
            "title": title,
            "business_impact": business_impact,
            "technologies": technologies,
            "semantic_labels": semantic_labels,
            "live_subdomains": [s.domain for s in live_subdomains],
            "open_ports": [
                {
                    "host": p.host,
                    "port": p.port,
                    "service": p.service,
                    "version": p.version,
                    "severity": p.severity,
                }
                for p in open_ports
            ],
            "analysis": analysis,
            "recommendations": recommendations,
        }
        return snapshot
    finally:
        db.close()


def _write_analysis_files(output_dir: Path, snapshot: Dict[str, Any]) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    md_path = output_dir / "analysis.md"
    json_path = output_dir / "analysis.json"

    md_lines = [
        "# Analysis Snapshot",
        "",
        f"Target: `{snapshot.get('target')}`",
        f"Session: `{snapshot.get('session_id')}`",
        f"Host: `{snapshot.get('selected_host')}`",
        f"Impact: `{snapshot.get('business_impact')}`",
        "",
        "## Narrative",
        snapshot.get("analysis", ""),
        "",
        "## Recommendations",
    ]
    for rec in snapshot.get("recommendations", []):
        md_lines.append(f"- {rec}")

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(snapshot, indent=2, default=str) + "\n", encoding="utf-8")

    return {"analysis_md": str(md_path), "analysis_json": str(json_path)}


def _generate_dummy_report(*_args: Any, **_kwargs: Any) -> None:
    """Compatibility no-op for legacy reporting tests."""
    return None


def execute_flow(
    target: str,
    *,
    analyze_host: Optional[str] = None,
    output: str = "reports/reales",
    allow_degraded: bool = False,
    dry_run: bool = False,
    threads: Optional[int] = None,
    speed: str = "normal",
    depth_level: int = 1,
    intent: str = "balanced",
    steroids: bool = True,
    ghost: bool = False,
    scan_profile: str = "safe-active",
    auth_file: Optional[str] = None,
    ui_enabled: bool = True,
) -> Dict[str, Any]:
    tool_manager.reset_timings()
    if ui_enabled:
        render_stage(
            "1/6",
            "Preflight",
            "Verifying runtime, folders, tools, intelligence engines and API contract.",
        )
    verification = _collect_verification(allow_degraded)
    if not verification["passed"] and not allow_degraded:
        if ui_enabled:
            render_outcome(
                "Preflight failed: one or more critical checks failed. Aborting before any active work.",
                border_style="red",
            )
        raise click.ClickException(
            "Verification failed. Re-run with --allow-degraded if you want to continue anyway."
        )

    if ui_enabled:
        render_stage(
            "2/6",
            "Scope & policy",
            "Validating target scope, scan profile, and authorization requirements.",
        )

    # Validate scan profile
    profile = get_profile(scan_profile)
    if not profile:
        raise click.ClickException(f"Invalid profile: {scan_profile}")

    # Set up scan context with profile timeout_policy
    from src.core.context import ScanContext, set_context
    scan_ctx = ScanContext(
        target=target,
        mode="flow",
        rate_limit=profile.rate_limit,
        timeout_policy=dict(profile.timeout_policy),
    )
    set_context(scan_ctx)

    # Check scope file (required for all scans)
    scope_file = Path("config/scope.yaml")
    if not scope_file.exists():
        if ui_enabled:
            console.print(
                "[yellow]Warning: No scope.yaml found in config/. Using target as implicit scope.[/yellow]"
            )
        # Create implicit scope for target
        _implicit_scope = {
            "target": target,
            "allowed_domains": [target, f"*.{target}"],
            "implicit": True,
        }
    else:
        with open(scope_file) as f:
            scope = yaml.safe_load(f)

        # Validate target is in scope
        target_domain = normalize_lookup_target(target)

        allowed = scope.get("allowed_domains", [])
        in_scope = host_in_allowed_domains(target_domain, allowed)

        if not in_scope:
            raise click.ClickException(
                f"Target '{target}' is not in scope. "
                f"Allowed domains: {allowed}. "
                "Edit config/scope.yaml to add this target."
            )

    # Check authorization for authorized profile
    if profile.requires_authorization and not auth_file:
        raise click.ClickException(
            f"Profile '{scan_profile}' requires authorization. "
            "Use --auth-file to specify authorization document."
        )

    if auth_file:
        auth_path = Path(auth_file)
        if not auth_path.exists():
            raise click.ClickException(f"Authorization file not found: {auth_file}")
        if ui_enabled:
            console.print(f"[yellow]Authorization loaded from: {auth_file}[/yellow]")

    if ui_enabled:
        console.print(f"[cyan]Using scan profile: {scan_profile}[/cyan] - {profile.description}")

    if dry_run:
        if ui_enabled:
            render_outcome(
                "Dry-run ready: verification and policy checks passed. No hunt will be executed."
            )
        return {
            "status": "dry_run",
            "target": target,
            "verification": verification,
            "flow_plan": {
                "target": target,
                "profile": scan_profile,
                "format": format,
                "dry_run": True,
            },
        }

    if ui_enabled:
        render_stage(
            "3/5",
            "Adaptive hunt execution",
            "Launching discovery, enrichment, scoring and intelligence loops.",
        )

    session_id = str(uuid.uuid4())
    scan_id: Optional[int] = None
    db_session = SessionLocal()
    try:
        db_queries = DBQueries(db_session)
        scan_record = db_queries.create_scan(
            target,
            session_id,
            mode="flow",
            status="running",
            start_time=datetime.now(timezone.utc),
        )
        scan_id = scan_record.id
    finally:
        db_session.close()

    try:
        hunt_result = _run_hunt(
            target,
            session_id,
            threads=threads,
            speed=speed,
            depth_level=depth_level,
            intent=intent,
            steroids=steroids,
            ghost=ghost,
            scan_profile=scan_profile,
            auth_file=auth_file,
        )

        if scan_id is not None:
            db_session = SessionLocal()
            try:
                db_queries = DBQueries(db_session)
                db_queries.update_scan_status(scan_id, "completed")
            finally:
                db_session.close()

        if ui_enabled:
            render_stage(
                "4/5",
                "Analysis snapshot",
                "Building local analysis artifacts and recommendations from the session data.",
            )

        safe_target = _safe_segment(target)
        session_dir = Path(output) / safe_target / session_id
        analysis_snapshot = _build_analysis_snapshot(target, session_id, analyze_host=analyze_host)
        artifact_paths = _write_analysis_files(session_dir, analysis_snapshot)
        report_path = _generate_dummy_report(session_dir, analysis_snapshot)

        db = SessionLocal()
        try:
            scan_obj = db.query(Scan).filter(Scan.session_id == session_id).first()
            if scan_obj:
                scan_obj.out_dir = str(session_dir)
                db.commit()
        finally:
            db.close()

        if ui_enabled:
            _render_data_summary(
                {"target": target, "analysis": analysis_snapshot, "session_dir": str(session_dir)}
            )
            render_stage(
                "5/5",
                "Diff intelligence",
                "Comparing this run against the previous baseline and summarizing changes.",
            )

        summary = {
            "status": "completed"
            if hunt_result.get("status") == "completed"
            else hunt_result.get("status", "unknown"),
            "target": target,
            "session_id": session_id,
            "session_dir": str(session_dir),
            "verification": verification,
            "hunt": hunt_result,
            "analysis": analysis_snapshot,
            "timing": tool_manager.get_timing_summary(),
            "artifacts": {
                **artifact_paths,
                "report": report_path,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "flow_summary.json").write_text(
            json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8"
        )

        if ui_enabled:
            render_timing_summary(summary["timing"])
            render_outcome("OzyRecon v1.2 Flow complete: artifacts and diff summary are ready.")

        dispatch_hook("scan_complete", summary)
        return summary

    except Exception:
        if scan_id is not None:
            db_session = SessionLocal()
            try:
                db_queries = DBQueries(db_session)
                db_queries.update_scan_status(scan_id, "failed")
            finally:
                db_session.close()
        raise


@click.command(name="flow")
@click.argument("target")
@click.option(
    "--output", type=click.Path(), default="reports/reales", help="Base directory for artifacts."
)
@click.option(
    "--analyze-host", type=str, default=None, help="Host to summarize in the analysis snapshot."
)
@click.option("--threads", default=None, type=int, help="Number of threads for hunt mode.")
@click.option(
    "--speed",
    default="normal",
    type=click.Choice(["slow", "normal", "fast"]),
    help="Speed mode for hunt.",
)
@click.option("--depth", "depth_level", default=1, type=int, help="Discovery depth.")
@click.option(
    "--intent",
    default="balanced",
    type=click.Choice(["passive", "balanced", "aggressive"]),
    help="Operational intent.",
)
@click.option(
    "--steroids/--no-steroids", default=True, help="Enable or disable enhanced recon steps."
)
@click.option("--ghost", is_flag=True, default=False, help="Enable ghost mode routing.")
@click.option(
    "--allow-degraded",
    is_flag=True,
    default=False,
    help="Continue even if verification is degraded.",
)
@click.option(
    "--dry-run", is_flag=True, default=False, help="Verify and plan only, do not execute the hunt."
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Print the final summary as JSON."
)
@click.option(
    "--profile",
    "scan_profile",
    type=click.Choice(["passive", "safe-active", "authorized"]),
    default="safe-active",
    help="Scan profile: passive (public only), safe-active (low impact), authorized (full).",
)
@click.option(
    "--auth-file", type=click.Path(), default=None, help="Authorization file for authorized scans."
)
@ensure_config_loaded()
def flow(
    target: str,
    output: str,
    analyze_host: Optional[str],
    threads: Optional[int],
    speed: str,
    depth_level: int,
    intent: str,
    steroids: bool,
    ghost: bool,
    allow_degraded: bool,
    dry_run: bool,
    json_output: bool,
    scan_profile: str,
    auth_file: Optional[str],
):
    """Run the full OzyRecon workflow in one shot."""
    try:
        if not json_output:
            _flow_plan(target, scan_profile, dry_run, allow_degraded)
            _flow_context(target, threads, speed, depth_level, intent, steroids, ghost)
        summary = execute_flow(
            target,
            analyze_host=analyze_host,
            output=output,
            allow_degraded=allow_degraded,
            dry_run=dry_run,
            threads=threads,
            speed=speed,
            depth_level=depth_level,
            intent=intent,
            steroids=steroids,
            ghost=ghost,
            scan_profile=scan_profile,
            auth_file=auth_file,
            ui_enabled=not json_output,
        )

        if json_output:
            click.echo(json.dumps(summary, indent=2, default=str))
            return summary

        _render_flow_results(summary, target)

        # Task: Show diff summary automatically
        try:
            db = SessionLocal()
            diff_engine = DiffEngine(db)
            scan_id = summary.get("session_id")  # We need the numeric ID though
            # Get numeric ID from session_id string
            scan_obj = db.query(Scan).filter(Scan.session_id == scan_id).first()
            if scan_obj:
                diff_report = diff_engine.get_diff(target, scan_obj.id)
                if diff_report.has_changes():
                    render_outcome("Attack surface changes detected", border_style="yellow")
                    console.print(f"[yellow]{diff_report.summary()}[/yellow]")
                    console.print(f"[dim]Run 'ozy diff {target}' for details.[/dim]\n")
                else:
                    render_outcome("No attack surface changes since last scan.")
            db.close()
        except Exception:
            pass

        report_path = summary.get("artifacts", {}).get("report")
        if report_path:
            console.print(f"[info]Report:[/info] {report_path}")
        console.print(f"[info]Analysis:[/info] {summary.get('artifacts', {}).get('analysis_md')}")
        return summary
    except Exception as e:
        handle_exception(e)
        raise click.ClickException(str(e))


__all__ = ["flow", "execute_flow"]
