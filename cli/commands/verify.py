"""
CLI command to verify OzyRecon runtime health.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import click
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.ozy import console, ensure_config_loaded, handle_exception
from src.core.manifest_manager import ManifestManager
from src.core.runtime_paths import get_runtime_root, safe_filename
from src.discovery.assets.recon import run_recon
from src.modes.hunt import run_hunt

ROOT_DIR = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT_DIR / "resources" / "manifest.yaml"

REQUIRED_TOOLS = {"subfinder", "dnsx", "httpx"}

CAPABILITY_NOTES = {
    "asset_discovery": "Baseline discovery. Missing binaries reduce breadth.",
    "dns_resolution": "Required for clean normalization. Missing binaries keep passive assets only.",
    "live_detection": "Required for live-host confirmation. Missing binaries keep resolved assets only.",
    "service_discovery": "Depth/coverage increases. Missing binaries reduce service fingerprints.",
    "port_scan": "Adds port coverage. Missing binaries reduce attack surface mapping.",
    "template_scan": "Adds template-based findings. Missing binaries reduce vuln coverage.",
}


def _build_capability_matrix() -> Dict[str, Any]:
    manager = ManifestManager()
    manifest = manager.load(str(MANIFEST_PATH))

    rows: List[Dict[str, Any]] = []
    required_missing = 0
    optional_missing = 0
    missing_required_tools: List[str] = []
    missing_optional_tools: List[str] = []
    ready_required_tools: List[str] = []

    for tool in manifest.tools:
        installed = shutil.which(tool.executable) is not None
        role = "required" if tool.executable in REQUIRED_TOOLS else "optional"
        status = "ready" if tool.enabled and installed else "degraded"

        if status != "ready":
            if role == "required":
                required_missing += 1
                missing_required_tools.append(tool.name)
            else:
                optional_missing += 1
                missing_optional_tools.append(tool.name)
        elif role == "required":
            ready_required_tools.append(tool.name)

        rows.append(
            {
                "name": tool.name,
                "binary": tool.executable,
                "capabilities": ", ".join(tool.categories),
                "role": role,
                "installed": installed,
                "enabled": tool.enabled,
                "status": status,
                "impact": CAPABILITY_NOTES.get(
                    tool.categories[0] if tool.categories else "",
                    "Missing binaries reduce coverage.",
                ),
            }
        )

    rows.sort(key=lambda item: (0 if item["role"] == "required" else 1, item["name"]))

    return {
        "tools": rows,
        "required_missing": required_missing,
        "optional_missing": optional_missing,
        "ready_required": len(REQUIRED_TOOLS) - required_missing,
        "missing_required_tools": missing_required_tools,
        "missing_optional_tools": missing_optional_tools,
        "ready_required_tools": ready_required_tools,
        "total_tools": len(rows),
    }


def _render_matrix(matrix: Dict[str, Any]) -> None:
    table = Table(title="Capability Matrix", header_style="bold cyan", show_lines=False)
    table.add_column("Tool", style="bold white")
    table.add_column("Capability", style="cyan")
    table.add_column("Role", justify="center")
    table.add_column("Binary", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Impact", style="dim")

    for row in matrix["tools"]:
        status_text = Text("ready", style="green") if row["status"] == "ready" else Text("degraded", style="yellow")
        role_text = Text(row["role"], style="bold green" if row["role"] == "required" else "dim")
        binary_text = row["binary"] if row["installed"] else f"{row['binary']} (missing)"

        table.add_row(
            row["name"],
            row["capabilities"],
            role_text,
            binary_text,
            status_text,
            row["impact"],
        )

    console.print(table)

    summary = Table(title="Readiness Summary", header_style="bold cyan")
    summary.add_column("Metric", style="bold white")
    summary.add_column("Value", style="white")
    summary.add_row("Required tools ready", f"{matrix['ready_required']}/{len(REQUIRED_TOOLS)}")
    summary.add_row("Required tools missing", str(matrix["required_missing"]))
    summary.add_row("Optional tools missing", str(matrix["optional_missing"]))
    summary.add_row(
        "Required missing list",
        ", ".join(matrix["missing_required_tools"]) if matrix["missing_required_tools"] else "-",
    )
    summary.add_row(
        "Optional missing list",
        ", ".join(matrix["missing_optional_tools"]) if matrix["missing_optional_tools"] else "-",
    )

    console.print(summary)

    if matrix["required_missing"]:
        console.print(
            Panel(
                "Baseline smoke is degraded until the required tools are available. "
                "Hunt and recon can still run, but coverage will be thinner.",
                title="Degradation",
                border_style="yellow",
            )
        )
    elif matrix["optional_missing"]:
        console.print(
            Panel(
                "Baseline smoke is ready. Optional tools are missing, so service, port, "
                "or template depth will be reduced.",
                title="Degradation",
                border_style="blue",
            )
        )
    else:
        console.print(
            Panel(
                "All declared tools are available. Full smoke and depth coverage should be possible.",
                title="Degradation",
                border_style="green",
            )
        )

    if matrix["ready_required_tools"]:
        console.print(
            Panel(
                "Ready required tools: " + ", ".join(matrix["ready_required_tools"]),
                title="Baseline Ready",
                border_style="green",
            )
        )


def _summarize_recon(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": "completed",
        "all_subdomains": len(result.get("all_subdomains", []) or []),
        "resolved": len(result.get("resolved", []) or []),
        "live_hosts": len(result.get("live_hosts", []) or []),
        "takeovers": len(result.get("takeovers", []) or []),
        "out_dir": result.get("out_dir"),
        "error": result.get("error"),
    }


def _summarize_hunt(result: Dict[str, Any]) -> Dict[str, Any]:
    result_payload = result.get("result") or {}
    stats = result_payload.get("stats") if isinstance(result_payload, dict) else {}
    return {
        "status": result.get("status", "completed"),
        "subdomains": result.get("subdomains", 0) or stats.get("subdomains_found", 0),
        "active_hosts": result.get("active_hosts", 0) or stats.get("hosts_alive", 0),
        "hypotheses": result.get("hypotheses", 0) or stats.get("findings", 0),
        "session_id": result.get("session_id"),
        "error": result.get("error"),
    }


@click.command(name="verify")
@click.argument("target", required=False)
@click.option(
    "--threads",
    default=1,
    show_default=True,
    type=int,
    help="Threads used for smoke runs.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable summary instead of tables.",
)
@click.option(
    "--allow-degraded",
    is_flag=True,
    help="Return success even when required binaries are missing.",
)
@ensure_config_loaded()
def verify(target: str | None, threads: int, json_output: bool, allow_degraded: bool) -> None:
    """
    Verify runtime health and optionally run a real hunt/recon smoke.

    When TARGET is provided, both recon and hunt are executed in a lightweight
    smoke profile using runtime paths outside the repository tree.
    """
    try:
        matrix = _build_capability_matrix()
        summary: Dict[str, Any] = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "manifest": str(MANIFEST_PATH),
            "capabilities": matrix,
        }
        exit_code = 0

        smoke: Dict[str, Any] = {"target": target}
        if target:
            runtime_root = get_runtime_root() / "verify" / safe_filename(target)
            recon_out = runtime_root / "recon"
            hunt_out = runtime_root / "hunt"
            recon_out.mkdir(parents=True, exist_ok=True)
            hunt_out.mkdir(parents=True, exist_ok=True)

            recon_summary: Dict[str, Any]
            hunt_summary: Dict[str, Any]

            try:
                recon_result = run_recon(target, recon_out, SimpleNamespace(threads=threads))
                recon_summary = _summarize_recon(recon_result)
            except Exception as exc:
                recon_summary = {"status": "failed", "error": str(exc), "out_dir": str(recon_out)}

            try:
                hunt_result = run_hunt(
                    target,
                    threads=threads,
                    speed="slow",
                    depth="shallow",
                    noise="low",
                    output=str(hunt_out),
                )
                hunt_summary = _summarize_hunt(hunt_result)
            except Exception as exc:
                hunt_summary = {"status": "failed", "error": str(exc), "out_dir": str(hunt_out)}

            smoke["recon"] = recon_summary
            smoke["hunt"] = hunt_summary

            if any(
                summary_part.get("status") == "failed"
                for summary_part in smoke.values()
                if isinstance(summary_part, dict)
            ):
                exit_code = 2

        summary["smoke"] = smoke

        if json_output:
            click.echo(json.dumps(summary, indent=2, default=str))
            should_fail = (matrix["required_missing"] > 0 and not allow_degraded) or bool(exit_code)
            raise SystemExit(2 if should_fail else 0)

        console.print(
            Panel(
                "OzyRecon runtime verification",
                subtitle="bootstrap + capability matrix" + (f" + smoke for {target}" if target else ""),
                border_style="cyan",
            )
        )
        _render_matrix(matrix)

        if target:
            smoke_table = Table(title=f"Smoke Runs for {target}", header_style="bold cyan")
            smoke_table.add_column("Phase", style="bold white")
            smoke_table.add_column("Status", justify="center")
            smoke_table.add_column("Details", style="dim")

            recon = smoke["recon"]
            hunt = smoke["hunt"]

            smoke_table.add_row(
                "recon",
                Text(recon.get("status", "unknown"), style="green" if recon.get("status") == "completed" else "red"),
                f"{recon.get('all_subdomains', 0)} subdomains, {recon.get('resolved', 0)} resolved, {recon.get('live_hosts', 0)} live",
            )
            smoke_table.add_row(
                "hunt",
                Text(hunt.get("status", "unknown"), style="green" if hunt.get("status") == "completed" else "red"),
                f"{hunt.get('subdomains', 0)} subdomains, {hunt.get('active_hosts', 0)} active, {hunt.get('hypotheses', 0)} hypotheses",
            )
            console.print(smoke_table)

        if (matrix["required_missing"] and not allow_degraded) or exit_code:
            raise SystemExit(2)
    except SystemExit:
        raise
    except Exception as exc:
        handle_exception(exc)
        raise SystemExit(1)
