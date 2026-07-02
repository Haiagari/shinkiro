"""
CLI Command: diff - Compare scans to detect changes in attack surface.
"""

import click
from rich.table import Table

from src.storage.database import SessionLocal
from src.core.target_normalizer import normalize_lookup_target
from src.storage.models import Scan, Target
from src.storage.diff import DiffEngine, DiffReport
from cli.shared import console, ensure_config_loaded, handle_exception, render_outcome, render_panel, render_plan, render_stage, render_timing_summary, load_timing_summary


def _render_diff_header(target: str, scan_id: int | None, previous_scan_id: int | None, output_format: str) -> None:
    plan_lines = [
        f"[bold]Target:[/bold] {target}",
        f"[bold]Output:[/bold] {output_format}",
        f"[bold]Current scan:[/bold] {scan_id or 'latest completed'}",
        f"[bold]Previous scan:[/bold] {previous_scan_id or 'auto-detected baseline'}",
        "",
        "[bold]Pipeline:[/bold]",
        "  1. Load target and baseline",
        "  2. Resolve current scan",
        "  3. Compute differential changes",
        "  4. Present surface changes",
    ]
    render_plan("PromptWall Diff", plan_lines)


def _render_diff_section(title: str, detail: str, border_style: str = "cyan") -> None:
    render_stage("Diff", title, detail, border_style=border_style)


def _render_empty_diff(target: str) -> None:
    render_outcome(f"No changes detected between scans for {target}.")


@click.command(name="diff")
@click.argument("target")
@click.option("--scan-id", type=int, default=None, help="Scan ID to compare (current). If not provided, uses last completed scan.")
@click.option("--previous-scan-id", type=int, default=None, help="Previous scan ID to compare against. If not provided, finds previous automatically.")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", help="Output format.")
@ensure_config_loaded()
def diff(target: str, scan_id: int | None, previous_scan_id: int | None, output_format: str):
    """
    Compare two scans for TARGET to detect changes in the attack surface.
    
    Shows new/removed subdomains, ports, services, and vulnerabilities.
    If no --scan-id is provided, compares the last two completed scans.
    """
    db = SessionLocal()
    try:
        ui_enabled = output_format != "json"
        if ui_enabled:
            _render_diff_header(target, scan_id, previous_scan_id, output_format)
            _render_diff_section("Load target", "Resolving the target and the comparison baseline.")
        lookup_target = normalize_lookup_target(target)
        target_obj = db.query(Target).filter(Target.domain == lookup_target).first()
        if not target_obj:
            if ui_enabled:
                render_outcome(f"Target '{target}' not found in database.", border_style="red")
            return

        if scan_id:
            if ui_enabled:
                _render_diff_section("Current scan", f"Using scan ID {scan_id} for {target}.")
            current_scan = db.query(Scan).filter(Scan.id == scan_id, Scan.target_id == target_obj.id).first()
            if not current_scan:
                if ui_enabled:
                    render_outcome(f"Scan {scan_id} not found for target '{target}'.", border_style="red")
                return
        else:
            if ui_enabled:
                _render_diff_section("Current scan", "Using the latest completed scan as the comparison source.")
            current_scan = db.query(Scan).filter(
                Scan.target_id == target_obj.id,
                Scan.status == "completed"
            ).order_by(Scan.id.desc()).first()
            
            if not current_scan:
                if ui_enabled:
                    render_outcome(f"No completed scans found for '{target}'.", border_style="red")
                return

        if ui_enabled:
            _render_diff_section("Diff calculation", f"Computing changes against {'scan ' + str(previous_scan_id) if previous_scan_id else 'the last available baseline' }.")
        diff_engine = DiffEngine(db)
        diff_report = diff_engine.get_diff(normalize_lookup_target(target), current_scan.id, previous_scan_id)
        diff_report.current_scan_out_dir = current_scan.out_dir

        if output_format == "json":
            import json
            console.print(json.dumps(diff_report.to_dict(), indent=2, default=list))
            return

        if ui_enabled:
            _render_diff_section("Presentation", "Formatting differential findings into readable sections.")
        _display_diff_report(target, diff_report)

    finally:
        db.close()


def _display_diff_report(target: str, report: DiffReport):
    """Display DiffReport in a readable table format."""
    render_panel(f"[bold cyan]Attack Surface Changes: {target}[/bold cyan]", border_style="cyan")

    if not report.has_changes():
        _render_empty_diff(target)
        return

    summary_lines = [
        f"[bold]Summary:[/bold] {report.summary()}",
        f"[bold]New subdomains:[/bold] {len(report.new_subdomains)}",
        f"[bold]Removed subdomains:[/bold] {len(report.removed_subdomains)}",
        f"[bold]Changed subdomains:[/bold] {len(report.changed_subdomains)}",
        f"[bold]New ports:[/bold] {len(report.new_ports)}",
        f"[bold]Closed ports:[/bold] {len(report.closed_ports)}",
        f"[bold]Changed services:[/bold] {len(report.changed_services)}",
        f"[bold]New findings:[/bold] {len(report.new_findings)}",
    ]
    render_plan("Diff Overview", summary_lines, border_style="green")

    if report.new_subdomains:
        _render_diff_section("New subdomains", f"{len(report.new_subdomains)} newly observed hostnames.", border_style="green")
        table = Table(title=f"New Subdomains (+{len(report.new_subdomains)})", border_style="green")
        table.add_column("Subdomain", style="cyan")
        for subdomain in report.new_subdomains[:20]:
            table.add_row(subdomain)
        if len(report.new_subdomains) > 20:
            table.add_row(f"... and {len(report.new_subdomains) - 20} more")
        console.print(table)
        console.print()

    if report.removed_subdomains:
        _render_diff_section("Removed subdomains", f"{len(report.removed_subdomains)} hosts disappeared from the latest scan.", border_style="red")
        table = Table(title=f"Removed Subdomains (-{len(report.removed_subdomains)})", border_style="red")
        table.add_column("Subdomain", style="dim")
        for subdomain in report.removed_subdomains[:20]:
            table.add_row(subdomain)
        if len(report.removed_subdomains) > 20:
            table.add_row(f"... and {len(report.removed_subdomains) - 20} more")
        console.print(table)
        console.print()

    if report.changed_subdomains:
        _render_diff_section("Metadata changes", f"{len(report.changed_subdomains)} subdomains changed attributes.", border_style="yellow")
        table = Table(title=f"Changed Subdomains (* {len(report.changed_subdomains)})", border_style="yellow")
        table.add_column("Subdomain", style="cyan")
        table.add_column("Changes", style="yellow")
        for change in report.changed_subdomains[:15]:
            changes_str = ", ".join(change["changes"].keys())
            table.add_row(change["domain"], changes_str)
        console.print(table)
        console.print()

    if report.new_ports:
        _render_diff_section("New ports", f"{len(report.new_ports)} ports are now visible.", border_style="green")
        table = Table(title=f"New Ports (+{len(report.new_ports)})", border_style="green")
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Service", style="white")
        for p in report.new_ports[:15]:
            table.add_row(p["host"], str(p["port"]), p.get("service", ""))
        console.print(table)
        console.print()

    if report.closed_ports:
        _render_diff_section("Closed ports", f"{len(report.closed_ports)} ports are no longer exposed.", border_style="red")
        table = Table(title=f"Closed Ports (-{len(report.closed_ports)})", border_style="red")
        table.add_column("Host", style="dim")
        table.add_column("Port", style="dim")
        for p in report.closed_ports[:15]:
            table.add_row(p["host"], str(p["port"]))
        console.print(table)
        console.print()

    if report.changed_services:
        _render_diff_section("Service changes", f"{len(report.changed_services)} services changed product or version.", border_style="yellow")
        table = Table(title=f"Changed Services (* {len(report.changed_services)})", border_style="yellow")
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="magenta")
        table.add_column("Old", style="dim")
        table.add_column("New", style="green")
        for s in report.changed_services[:15]:
            old_str = f"{s['old'].get('service', '')} {s['old'].get('version', '')}"
            new_str = f"{s['new'].get('service', '')} {s['new'].get('version', '')}"
            table.add_row(s["host"], str(s["port"]), old_str, new_str)
        console.print(table)
        console.print()

    if report.new_findings:
        _render_diff_section("New findings", f"{len(report.new_findings)} findings appeared in this baseline comparison.", border_style="red")
        console.print(f"[bold red]New Findings (! {len(report.new_findings)})[/bold red]")
        for finding in report.new_findings[:10]:
            console.print(f"  • {finding}")
        if len(report.new_findings) > 10:
            console.print(f"  ... and {len(report.new_findings) - 10} more")
        console.print()

    timing = load_timing_summary(getattr(report, "current_scan_out_dir", None))
    if timing:
        render_timing_summary(timing)

    console.print(f"[dim]Summary: {report.summary()}[/dim]")


__all__ = ["diff"]
