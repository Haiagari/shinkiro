from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests
from rich.box import SIMPLE_HEAVY
from rich.align import Align
from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from backend.modules.database import SessionLocal, init_db
from backend.modules.db_queries import get_latest_scan, get_scan_history, get_scan_diff, get_target_stats
from backend.modules.models import Scan, Target, Vulnerability, Subdomain, Port, AgentMemory
from backend.modules.utils import load_json
from ui.renderer import console


ROOT_DIR = Path(__file__).resolve().parents[1]
API_BASE = os.getenv("BBUG_API_URL", "http://localhost:5000").rstrip("/")
CLI_STATE_FILE = ROOT_DIR / "runtime" / "state" / "agent_cli_state.json"
TERMINAL_STATUSES = {"completed", "error", "failed", "cancelled", "canceled", "idle"}


def is_terminal_status(status: str | None) -> bool:
    return (status or "idle").strip().lower() in TERMINAL_STATUSES


def normalize_status_label(status: str | None) -> str:
    value = (status or "idle").strip().lower()
    mapping = {
        "running": "EN CURSO",
        "completed": "COMPLETADO",
        "error": "ERROR",
        "failed": "ERROR",
        "cancelled": "CANCELADO",
        "canceled": "CANCELADO",
        "idle": "IDLE",
    }
    return mapping.get(value, value.upper())


def render_progress_bar(progress: int, width: int = 24) -> Text:
    value = max(0, min(100, int(progress or 0)))
    filled = round((value / 100) * width)
    t = Text()
    t.append("█" * filled, style="accent")
    t.append("░" * (width - filled), style="muted")
    t.append(f"  {value}%")
    return t


@dataclass
class ScanOptions:
    full: bool = False
    recon: bool = False
    ports: bool = False
    urls: bool = False
    vulns: bool = False
    report: bool = False
    waf_detection: bool = False
    active_fuzz: bool = False
    threads: int = 50
    timeout: int = 10
    program: Optional[str] = None
    agent: Optional[str] = None
    output: Optional[str] = None


def normalize_target(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = value.removeprefix("http://").removeprefix("https://").rstrip("/")
    return value


def load_cli_state() -> dict:
    state = load_json(CLI_STATE_FILE)
    return state if isinstance(state, dict) else {}


def save_cli_state(state: dict) -> None:
    CLI_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CLI_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def get_focused_target() -> str | None:
    state = load_cli_state()
    target = state.get("focused_target")
    return normalize_target(target) if target else None


def set_focused_target(target: str) -> str:
    target_clean = normalize_target(target)
    state = load_cli_state()
    state["focused_target"] = target_clean
    state["updated_at"] = datetime.utcnow().isoformat()
    save_cli_state(state)
    return target_clean


def resolve_target(target: str | None) -> str | None:
    if target and target.strip():
        return normalize_target(target)
    return get_focused_target()


def build_scan_command(target: str, opts: ScanOptions) -> list[str]:
    cmd = [sys.executable, str(ROOT_DIR / "backend" / "main.py"), "-t", normalize_target(target)]
    if opts.output:
        cmd += ["-o", opts.output]
    if opts.program:
        cmd += ["-p", opts.program]
    if opts.full:
        cmd.append("--full")
    if opts.recon:
        cmd.append("--recon")
    if opts.ports:
        cmd.append("--ports")
    if opts.urls:
        cmd.append("--urls")
    if opts.vulns:
        cmd.append("--vulns")
    if opts.report:
        cmd.append("--report")
    if opts.waf_detection:
        cmd.append("--waf-detection")
    if opts.active_fuzz:
        cmd.append("--active-fuzz")
    if opts.agent:
        cmd += ["--agent", opts.agent]
    if opts.threads:
        cmd += ["--threads", str(opts.threads)]
    if opts.timeout:
        cmd += ["--timeout", str(opts.timeout)]
    return cmd


def _scan_status_from_outdir(out_dir: str | None) -> dict:
    if not out_dir:
        return {}
    status_path = Path(out_dir) / "status.json"
    if not status_path.exists():
        return {}
    return load_json(status_path)


def _scan_payload(scan: Scan, db) -> dict:
    target_obj = db.query(Target).filter(Target.id == scan.target_id).first()
    status = _scan_status_from_outdir(scan.out_dir)
    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan.id).all()
    ports = db.query(Port).filter(Port.scan_id == scan.id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()

    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "target": target_obj.domain if target_obj else "n/a",
        "status": status.get("status", scan.status or "completed"),
        "phase": status.get("phase", "unknown"),
        "progress": status.get("progress", 100 if scan.status == "completed" else 0),
        "message": status.get("message", ""),
        "error": status.get("error"),
        "updated_at": status.get("updated_at"),
        "started_at": scan.start_time.isoformat() if scan.start_time else None,
        "timestamp": scan.timestamp,
        "out_dir": scan.out_dir,
        "counts": {
            "subdomains": len(subdomains),
            "live_hosts": sum(1 for sub in subdomains if sub.is_live),
            "ports": len(ports),
            "vulns": len(vulns),
            "critical": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "critical"),
            "high": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "high"),
            "medium": sum(1 for vuln in vulns if (vuln.severity or "").lower() == "medium"),
        },
        "events": status.get("history", [])[-4:],
    }


def _latest_scan_for_target(target: str | None) -> Scan | None:
    init_db()
    with SessionLocal() as db:
        if target:
            return get_latest_scan(db, normalize_target(target))
        return db.query(Scan).order_by(Scan.id.desc()).first()


def _local_dashboard_state(target: str | None = None) -> dict | None:
    init_db()
    with SessionLocal() as db:
        latest_scan = get_latest_scan(db, normalize_target(target)) if target else db.query(Scan).order_by(Scan.id.desc()).first()
        if not latest_scan:
            return None

        target_obj = db.query(Target).filter(Target.id == latest_scan.target_id).first()
        if not target_obj:
            return None

        status = _scan_status_from_outdir(latest_scan.out_dir)
        stats = get_target_stats(db, target_obj.domain)
        scan_events = status.get("history", [])

        findings_payload = []
        for vuln in latest_scan.vulnerabilities:
            sev = (vuln.severity or "medium").lower()
            cvss_map = {"critical": 9.8, "high": 8.0, "medium": 5.3, "low": 2.1, "info": 0.0}
            findings_payload.append({
                "id": f"finding-{vuln.id}",
                "severity": sev,
                "badge": sev[:4].upper(),
                "severityLabel": sev.capitalize(),
                "title": getattr(vuln, "name", None) or vuln.type,
                "target": target_obj.domain,
                "location": vuln.url or "n/a",
                "cvss": cvss_map.get(sev, 5.0),
                "summary": vuln.description or "Sin descripción",
                "impact": vuln.description or "Pendiente de análisis",
                "evidence": [],
                "remediation": [],
                "tags": [vuln.type] if vuln.type else [],
            })

        memories = db.query(AgentMemory).filter(AgentMemory.target == target_obj.domain).order_by(AgentMemory.created_at.desc()).all()
        target_payload = _build_target_payload(target_obj, db)
        recent_history = get_history(limit=8)

        return {
            "project": {
                "name": "BugBounty Framework",
                "run": f"scan #{latest_scan.id}",
                "target": target_obj.domain,
                "mode": status.get("mode", "HUNT"),
                "status": status.get("status", latest_scan.status if latest_scan else "idle"),
            },
            "stats": {
                "subdomains": stats.get("total_subdomains", 0),
                "hosts": stats.get("live_subdomains", 0),
                "ports": stats.get("total_ports", 0),
                "steps": len(scan_events) or 0,
                "score": min(1, ((stats.get("critical_count", 0) * 0.18) + (stats.get("high_count", 0) * 0.08) + 0.3)),
            },
            "targets": [target_payload],
            "findings": findings_payload,
            "logs": [
                {
                    "time": event.get("time", "--:--"),
                    "level": {"running": "agent", "completed": "ok", "error": "crit", "warn": "warn"}.get(event.get("status", "running"), "info"),
                    "label": event.get("phase", "PHASE").upper(),
                    "message": event.get("message", ""),
                }
                for event in scan_events
            ][-14:],
            "liveLogFeed": [
                {
                    "time": event.get("time", "--:--"),
                    "level": {"running": "agent", "completed": "ok", "error": "crit", "warn": "warn"}.get(event.get("status", "running"), "info"),
                    "label": event.get("phase", "PHASE").upper(),
                    "message": event.get("message", ""),
                }
                for event in scan_events
            ][-6:],
            "memory": [
                {
                    "key": memory.key,
                    "value": memory.value,
                    "confidence": memory.confidence,
                }
                for memory in memories
            ],
            "modes": [
                {"name": "HUNT", "icon": "⚡", "status": "ACTIVE" if status.get("status") == "running" else "DISPONIBLE", "running": True, "desc": "Scan agresivo en target"},
                {"name": "CONTINUO", "icon": "◎", "status": "DISPONIBLE", "running": False, "desc": "Monitor 24/7 con diff"},
                {"name": "CAMPAÑA", "icon": "▦", "status": "DISPONIBLE", "running": False, "desc": "Patrón en múltiples targets"},
                {"name": "INVESTIGACIÓN", "icon": "🔬", "status": "DISPONIBLE", "running": False, "desc": "CVE en superficie conocida"},
            ],
            "chart": {
                "labels": [event.get("phase", str(i + 1)) for i, event in enumerate(scan_events)] if scan_events else ["0"],
                "values": [event.get("progress", 0) for event in scan_events] if scan_events else [0],
            },
            "scan_status": {
                "target": target_obj.domain,
                "scan_id": latest_scan.id,
                "status": status.get("status", latest_scan.status if latest_scan else "idle"),
                "phase": status.get("phase", "unknown"),
                "progress": status.get("progress", 0),
                "message": status.get("message", ""),
                "error": status.get("error"),
                "updated_at": status.get("updated_at"),
                "events": scan_events,
            },
            "scan_history": recent_history,
        }


def _build_target_payload(target_obj: Target, db) -> dict:
    latest_scan = get_latest_scan(db, target_obj.domain)
    status = _scan_status_from_outdir(latest_scan.out_dir) if latest_scan else {}
    subs = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all() if latest_scan else []
    ports = db.query(Port).filter(Port.scan_id == latest_scan.id).all() if latest_scan else []
    vulns = latest_scan.vulnerabilities if latest_scan else []
    live_subs = [s for s in subs if s.is_live]

    return {
        "id": f"target-{target_obj.id}",
        "host": target_obj.domain,
        "mode": status.get("mode", "hunt"),
        "modeClass": "mode-hunt",
        "modeLabel": f"⚡ {status.get('mode', 'HUNT').upper()}",
        "modeName": status.get("mode", "HUNT").upper(),
        "findings": {
            "critical": sum(1 for v in vulns if (v.severity or "").lower() == "critical"),
            "high": sum(1 for v in vulns if (v.severity or "").lower() == "high"),
            "medium": sum(1 for v in vulns if (v.severity or "").lower() == "medium"),
        },
        "progress": status.get("progress", 100 if latest_scan and latest_scan.status == "completed" else 0),
        "lastScan": latest_scan.timestamp if latest_scan and latest_scan.timestamp else (latest_scan.start_time.strftime("%H:%M") if latest_scan and latest_scan.start_time else "n/a"),
        "ip": (live_subs[0].ip if live_subs and live_subs[0].ip else "n/a") if live_subs else "n/a",
        "hosting": "DB-backed scan",
        "techStack": (live_subs[0].web_server if live_subs and live_subs[0].web_server else "n/a") if live_subs else "n/a",
        "surface": f"{len(live_subs)} hosts · {len(ports)} puertos",
        "notes": [
            f"{event.get('phase', 'phase')}: {event.get('message', '')}"
            for event in status.get("history", [])[-2:]
        ] or [f"Scan {latest_scan.status}" if latest_scan else "Sin scans"],
    }


def _render_status_panel(payload: dict, *, title: str = "Estado") -> Panel:
    counts = payload.get("counts", {})
    body = Text()
    body.append("Target ", style="muted")
    body.append(f"{payload.get('target', 'n/a')}\n", style="accent bold")
    body.append("Estado ", style="muted")
    body.append(f"{normalize_status_label(payload.get('status'))}\n", style="ok")
    body.append("Fase   ", style="muted")
    body.append(f"{payload.get('phase', 'none')}\n", style="observe")
    body.append("Progreso ", style="muted")
    body.append_text(render_progress_bar(payload.get("progress", 0)))
    body.append("\n")
    if payload.get("message"):
        body.append("Mensaje ", style="muted")
        body.append(f"{payload.get('message')}\n")
    if payload.get("error"):
        body.append("Error ", style="muted")
        body.append(f"{payload.get('error')}\n", style="fail")
    if counts:
        body.append("Datos ", style="muted")
        body.append(
            f"{counts.get('subdomains', 0)} subs · {counts.get('live_hosts', 0)} hosts vivos · "
            f"{counts.get('ports', 0)} puertos · {counts.get('vulns', 0)} vulns\n",
            style="host",
        )
    if payload.get("updated_at"):
        body.append("Actualizado ", style="muted")
        body.append(f"{payload.get('updated_at')}\n")
    return Panel(body, title=title, border_style="accent")


def _render_events_table(events: list[dict], *, title: str = "Eventos recientes") -> Table | None:
    if not events:
        return None
    table = Table(title=title, box=SIMPLE_HEAVY, show_lines=False, expand=True)
    table.add_column("Hora", style="muted", no_wrap=True)
    table.add_column("Fase", style="accent", no_wrap=True)
    table.add_column("Estado", style="white", no_wrap=True)
    table.add_column("Mensaje", style="white")
    for event in events[-6:]:
        table.add_row(
            event.get("time", "--:--"),
            event.get("phase", "n/a"),
            normalize_status_label(event.get("status")),
            event.get("message", ""),
        )
    return table


def _render_counts_table(payload: dict, *, title: str = "Resumen") -> Table:
    counts = payload.get("counts", {})
    table = Table(title=title, box=SIMPLE_HEAVY, show_lines=False)
    table.add_column("Subdominios", justify="right", style="accent")
    table.add_column("Hosts vivos", justify="right", style="green")
    table.add_column("Puertos", justify="right", style="cyan")
    table.add_column("Críticos", justify="right", style="red")
    table.add_column("Altos", justify="right", style="yellow")
    table.add_column("Medios", justify="right", style="white")
    table.add_row(
        str(counts.get("subdomains", 0)),
        str(counts.get("live_hosts", 0)),
        str(counts.get("ports", 0)),
        str(counts.get("critical", 0)),
        str(counts.get("high", 0)),
        str(counts.get("medium", 0)),
    )
    return table


def get_history(target: str | None = None, limit: int = 10) -> list[dict]:
    init_db()
    with SessionLocal() as db:
        if target:
            scans = get_scan_history(db, normalize_target(target), days=3650)[:limit]
        else:
            scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
        return [_scan_payload(scan, db) for scan in scans]


def get_latest_status(target: str | None = None) -> dict:
    init_db()
    with SessionLocal() as db:
        if target:
            latest_scan = get_latest_scan(db, normalize_target(target))
            if not latest_scan:
                return {"target": normalize_target(target), "status": "idle", "phase": "none", "progress": 0, "events": []}
        else:
            latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
            if not latest_scan:
                return {"status": "idle", "phase": "none", "progress": 0, "events": []}
        return _scan_payload(latest_scan, db)


def api_alive(timeout: float = 2.0) -> bool:
    try:
        response = requests.get(f"{API_BASE}/stats", timeout=timeout)
        return response.ok
    except Exception:
        return False


def api_json(path: str, timeout: float = 3.0) -> dict | list | None:
    try:
        response = requests.get(f"{API_BASE}{path}", timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def print_status(target: str | None = None) -> None:
    target_clean = resolve_target(target)
    payload = get_latest_status(target_clean)
    title = f"Status · {payload.get('target', 'latest')}"
    panel = Panel(
        "\n".join(
            [
                f"[bold]Estado:[/] {payload.get('status', 'idle')}",
                f"[bold]Fase:[/] {payload.get('phase', 'none')}",
                f"[bold]Progreso:[/] {payload.get('progress', 0)}%",
                f"[bold]Mensaje:[/] {payload.get('message') or '—'}",
                f"[bold]Ruta:[/] {payload.get('out_dir') or '—'}",
            ]
        ),
        title=title,
        border_style="cyan",
    )
    console.print(panel)
    if payload.get("events"):
        table = Table(title="Eventos recientes", box=SIMPLE_HEAVY, show_lines=False)
        table.add_column("Hora", style="muted", no_wrap=True)
        table.add_column("Fase", style="accent")
        table.add_column("Mensaje", style="white")
        for event in payload["events"][-4:]:
            table.add_row(event.get("time", "--:--"), event.get("phase", "n/a"), event.get("message", ""))
        console.print(table)


def print_history(target: str | None = None, limit: int = 10) -> None:
    items = get_history(resolve_target(target), limit=limit)
    if not items:
        console.print(Panel("Sin historial todavía.", title="History", border_style="yellow"))
        return

    table = Table(title="Historial de scans", box=SIMPLE_HEAVY, show_lines=False)
    table.add_column("#", style="muted", no_wrap=True)
    table.add_column("Target", style="cyan")
    table.add_column("Estado", style="green")
    table.add_column("Fase", style="magenta")
    table.add_column("Progreso", style="yellow", justify="right")
    table.add_column("C/H/M", style="white")
    table.add_column("Inicio", style="muted")
    for item in items:
        counts = item.get("counts", {})
        table.add_row(
            str(item.get("scan_id", "")),
            item.get("target", "n/a"),
            item.get("status", "n/a"),
            item.get("phase", "n/a"),
            f"{item.get('progress', 0)}%",
            f"{counts.get('critical', 0)}/{counts.get('high', 0)}/{counts.get('medium', 0)}",
            item.get("started_at", "n/a"),
        )
    console.print(table)


def print_report(target: str | None = None) -> None:
    payload = get_latest_status(resolve_target(target))
    if not payload:
        console.print(Panel("Sin datos para reportar.", title="Report", border_style="red"))
        return
    counts = payload.get("counts", {})
    panel = Panel(
        "\n".join(
            [
                f"[bold]Target:[/] {payload.get('target', 'n/a')}",
                f"[bold]Estado:[/] {payload.get('status', 'n/a')}",
                f"[bold]Fase:[/] {payload.get('phase', 'n/a')}",
                f"[bold]Progreso:[/] {payload.get('progress', 0)}%",
                f"[bold]Subdominios:[/] {counts.get('subdomains', 0)}",
                f"[bold]Hosts vivos:[/] {counts.get('live_hosts', 0)}",
                f"[bold]Puertos:[/] {counts.get('ports', 0)}",
                f"[bold]Vulns:[/] {counts.get('vulns', 0)}",
                f"[bold]Ruta:[/] {payload.get('out_dir') or 'n/a'}",
            ]
        ),
        title="Último reporte",
        border_style="cyan",
    )
    console.print(panel)


def print_doctor() -> None:
    init_db()
    with SessionLocal() as db:
        stats = {
            "targets": db.query(Target).count(),
            "scans": db.query(Scan).count(),
            "subdomains": db.query(Subdomain).count(),
            "ports": db.query(Port).count(),
            "vulns": db.query(Vulnerability).count(),
        }

    table = Table(title="Doctor", box=SIMPLE_HEAVY)
    table.add_column("Check", style="accent")
    table.add_column("Estado", style="white")
    table.add_column("Detalle", style="muted")

    checks = [
        ("API", "OK" if api_alive() else "DOWN", API_BASE),
        ("DB", "OK" if (ROOT_DIR / "runtime" / "db" / "ozyrecon.db").exists() else "MISSING", str(ROOT_DIR / "runtime" / "db" / "ozyrecon.db")),
        ("Runtime", "OK" if (ROOT_DIR / "runtime" / "scans").exists() else "MISSING", str(ROOT_DIR / "runtime" / "scans")),
        ("Python", "OK" if shutil.which("python3") else "MISSING", "python3"),
    ]
    for label, state, detail in checks:
        table.add_row(label, state, detail)

    console.print(table)
    console.print(
        Panel(
            f"Targets: {stats['targets']}\nScans: {stats['scans']}\nSubdomains: {stats['subdomains']}\nPorts: {stats['ports']}\nVulns: {stats['vulns']}",
            title="DB stats",
            border_style="green",
        )
    )


def print_dashboard() -> None:
    """Muestra el dashboard de inteligencia reflexiva."""
    from src.intelligence.dashboard import show_dashboard
    show_dashboard()


def build_export_payload(target: str | None = None) -> dict | None:
    target_clean = resolve_target(target)
    payload = api_json(f"/dashboard-state?target={quote(target_clean)}" if target_clean else "/dashboard-state")
    if not isinstance(payload, dict):
        payload = _local_dashboard_state(target_clean)
    if not isinstance(payload, dict):
        return None

    init_db()
    with SessionLocal() as db:
        diff = {}
        if target_clean:
            try:
                diff = get_scan_diff(db, target_clean)
            except Exception:
                diff = {}
        latest = get_latest_scan(db, target_clean) if target_clean else db.query(Scan).order_by(Scan.id.desc()).first()
        scan_payload = _scan_payload(latest, db) if latest else {}

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "target": target_clean or payload.get("project", {}).get("target"),
        "project": payload.get("project", {}),
        "stats": payload.get("stats", {}),
        "scan_status": payload.get("scan_status", {}),
        "targets": payload.get("targets", []),
        "findings": payload.get("findings", []),
        "logs": payload.get("logs", []),
        "liveLogFeed": payload.get("liveLogFeed", []),
        "memory": payload.get("memory", []),
        "modes": payload.get("modes", []),
        "chart": payload.get("chart", {}),
        "scan_history": payload.get("scan_history", []),
        "scan": scan_payload,
        "diff": diff,
    }


def print_diff(target: str | None = None) -> None:
    target_clean = resolve_target(target)
    if not target_clean:
        console.print(Panel("Usa: diff <target> o focus <target> primero.", title="Diff", border_style="yellow"))
        return

    init_db()
    with SessionLocal() as db:
        try:
            diff = get_scan_diff(db, target_clean)
        except Exception as exc:
            console.print(Panel(f"No se pudo calcular diff: {exc}", title="Diff", border_style="red"))
            return

    if diff.get("error"):
        console.print(Panel(str(diff["error"]), title="Diff", border_style="red"))
        return

    panel = Panel(
        "\n".join(
            [
                f"[bold]Target:[/] {target_clean}",
                f"[bold]First run:[/] {diff.get('is_first_run', False)}",
                f"[bold]New subdomains:[/] {len(diff.get('new_subdomains', []))}",
                f"[bold]New ports:[/] {len(diff.get('new_ports', []))}",
                f"[bold]New vulns:[/] {len(diff.get('new_vulns', []))}",
                f"[bold]Total vulns:[/] {diff.get('total_vulns', 0)}",
            ]
        ),
        title="Diff",
        border_style="accent",
    )
    console.print(panel)

    if diff.get("new_subdomains"):
        table = Table(title="Nuevos subdominios", box=SIMPLE_HEAVY, show_lines=False)
        table.add_column("Dominio", style="accent")
        table.add_column("Activo", style="white")
        for item in diff["new_subdomains"][:12]:
            table.add_row(item.get("domain", "n/a"), "sí" if item.get("is_live") else "no")
        console.print(table)

    if diff.get("new_ports"):
        table = Table(title="Nuevos puertos", box=SIMPLE_HEAVY, show_lines=False)
        table.add_column("Host", style="accent")
        table.add_column("Puerto", style="white")
        table.add_column("Servicio", style="muted")
        for item in diff["new_ports"][:12]:
            table.add_row(item.get("host", "n/a"), str(item.get("port", "n/a")), item.get("service", "n/a"))
        console.print(table)

    if diff.get("new_vulns"):
        table = Table(title="Nuevas vulnerabilidades", box=SIMPLE_HEAVY, show_lines=False)
        table.add_column("Tipo", style="accent")
        table.add_column("Severidad", style="white")
        table.add_column("URL", style="muted")
        table.add_column("CVE", style="yellow")
        for item in diff["new_vulns"][:12]:
            table.add_row(item.get("type", "n/a"), item.get("severity", "n/a"), item.get("url", "n/a"), item.get("cve", "n/a"))
        console.print(table)


def focus_target(target: str | None) -> str | None:
    target_clean = resolve_target(target)
    if not target_clean:
        current = get_focused_target()
        if current:
            console.print(Panel(f"Target activo: [accent]{current}[/accent]", title="Focus", border_style="accent"))
            return current
        console.print(Panel("Usa: focus <target>.", title="Focus", border_style="yellow"))
        return None
    set_focused_target(target_clean)
    payload = get_latest_status(target_clean)
    console.print(
        Panel(
            f"Target activo: [accent]{target_clean}[/accent]\nEstado: [bold]{normalize_status_label(payload.get('status'))}[/bold]\nFase: {payload.get('phase', 'none')}",
            title="Focus",
            border_style="accent",
        )
    )
    return target_clean


def export_summary(target: str | None = None, fmt: str = "json", output: str | None = None) -> Path | None:
    payload = build_export_payload(target)
    if not payload:
        console.print(Panel("No hay datos para exportar.", title="Export", border_style="yellow"))
        return None

    target_clean = payload.get("target") or "latest"
    export_dir = ROOT_DIR / "runtime" / "exports" / normalize_target(target_clean)
    export_dir.mkdir(parents=True, exist_ok=True)
    fmt_clean = (fmt or "json").strip().lower()
    if fmt_clean not in {"json", "md", "markdown"}:
        fmt_clean = "json"

    if output:
        out_path = Path(output)
        if not out_path.is_absolute():
            out_path = ROOT_DIR / output
    else:
        ext = "md" if fmt_clean in {"md", "markdown"} else "json"
        out_path = export_dir / f"summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{ext}"

    if fmt_clean in {"md", "markdown"}:
        scan_status = payload.get("scan_status", {})
        lines = [
            f"# BugBounty Framework Export",
            "",
            f"- Target: `{payload.get('target', 'n/a')}`",
            f"- Generated at: `{payload.get('generated_at', 'n/a')}`",
            f"- Status: `{normalize_status_label(scan_status.get('status'))}`",
            f"- Phase: `{scan_status.get('phase', 'n/a')}`",
            f"- Progress: `{scan_status.get('progress', 0)}%`",
            "",
            "## Stats",
            f"- Subdomains: {payload.get('stats', {}).get('subdomains', 0)}",
            f"- Hosts vivos: {payload.get('stats', {}).get('hosts', 0)}",
            f"- Puertos: {payload.get('stats', {}).get('ports', 0)}",
            f"- Findings: {len(payload.get('findings', []))}",
            "",
            "## Diff",
            f"- Nuevos subdominios: {len(payload.get('diff', {}).get('new_subdomains', []))}",
            f"- Nuevos puertos: {len(payload.get('diff', {}).get('new_ports', []))}",
            f"- Nuevas vulns: {len(payload.get('diff', {}).get('new_vulns', []))}",
        ]
        out_path.write_text("\n".join(lines), encoding="utf-8")
    else:
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    console.print(Panel(f"Export guardado en {out_path}", title="Export", border_style="green"))
    return out_path


def print_overview(target: str | None = None) -> None:
    target_clean = resolve_target(target)
    payload = api_json(f"/dashboard-state?target={quote(target_clean)}" if target_clean else "/dashboard-state")
    if not isinstance(payload, dict):
        payload = _local_dashboard_state(target_clean)
    if not isinstance(payload, dict):
        console.print(Panel("No se pudo leer el estado del framework.", title="Overview", border_style="red"))
        return

    project = payload.get("project", {})
    scan_status = payload.get("scan_status", {})
    targets = payload.get("targets", [])
    findings = payload.get("findings", [])
    history = payload.get("scan_history", [])
    modes = payload.get("modes", [])

    header = Panel(
        Text.from_markup(
            "\n".join(
                [
                    f"[accent bold]{project.get('name', 'BugBounty Framework')}[/accent bold]",
                    f"[muted]Run[/muted] {project.get('run', 'n/a')}  ·  [muted]Target[/muted] {project.get('target', 'n/a')}",
                    f"[muted]Mode[/muted] {project.get('mode', 'n/a')}  ·  [muted]Estado[/muted] {normalize_status_label(project.get('status'))}",
                ]
            )
        ),
        title="Overview",
        border_style="accent",
    )
    console.print(header)
    console.print(_render_counts_table(payload, title="Resumen operativo"))
    console.print(_render_status_panel(scan_status or payload, title="Estado del run"))

    if targets:
        target_table = Table(title="Targets activos", box=SIMPLE_HEAVY, show_lines=False, expand=True)
        target_table.add_column("Target", style="accent", no_wrap=False)
        target_table.add_column("Estado", style="white", no_wrap=True)
        target_table.add_column("Modo", style="cyan", no_wrap=True)
        target_table.add_column("Progreso", style="yellow", no_wrap=True)
        target_table.add_column("Señal", style="green")
        for item in targets[:6]:
            target_table.add_row(
                item.get("host", "n/a"),
                normalize_status_label(project.get("status")),
                item.get("modeName", "HUNT"),
                f"{item.get('progress', 0)}%",
                item.get("surface", "—"),
            )
        console.print(target_table)

    if findings:
        findings_table = Table(title="Hallazgos recientes", box=SIMPLE_HEAVY, show_lines=False, expand=True)
        findings_table.add_column("Sev", style="accent", no_wrap=True)
        findings_table.add_column("Título", style="white")
        findings_table.add_column("Ubicación", style="muted")
        findings_table.add_column("CVSS", style="yellow", justify="right")
        for item in findings[:6]:
            findings_table.add_row(
                item.get("severityLabel", item.get("severity", "n/a")).upper(),
                item.get("title", "n/a"),
                item.get("location", "n/a"),
                f"{item.get('cvss', 0):.1f}",
            )
        console.print(findings_table)

    if modes:
        modes_table = Table(title="Modos operativos", box=SIMPLE_HEAVY, show_lines=False, expand=True)
        modes_table.add_column("Modo", style="accent")
        modes_table.add_column("Estado", style="white", no_wrap=True)
        modes_table.add_column("Descripción", style="muted")
        for mode in modes:
            modes_table.add_row(
                mode.get("name", "n/a"),
                mode.get("status", "n/a"),
                mode.get("desc", ""),
            )
        console.print(modes_table)

    if history:
        history_table = Table(title="Historia reciente", box=SIMPLE_HEAVY, show_lines=False, expand=True)
        history_table.add_column("#", style="muted", no_wrap=True)
        history_table.add_column("Target", style="accent")
        history_table.add_column("Estado", style="white")
        history_table.add_column("Fase", style="cyan")
        history_table.add_column("Progreso", style="yellow", justify="right")
        for item in history[:6]:
            history_table.add_row(
                str(item.get("scan_id", "")),
                item.get("target", "n/a"),
                normalize_status_label(item.get("status")),
                item.get("phase", "n/a"),
                f"{item.get('progress', 0)}%",
            )
        console.print(history_table)


def print_targets() -> None:
    init_db()
    with SessionLocal() as db:
        targets = db.query(Target).order_by(Target.added_at.desc()).all()
        if not targets:
            console.print(Panel("No hay targets todavía.", title="Targets", border_style="yellow"))
            return

        table = Table(title="Targets", box=SIMPLE_HEAVY, show_lines=False, expand=True)
        table.add_column("Target", style="accent")
        table.add_column("Estado", style="white")
        table.add_column("Fase", style="cyan")
        table.add_column("Progreso", style="yellow", justify="right")
        table.add_column("Subs", style="green", justify="right")
        table.add_column("Hosts", style="green", justify="right")
        table.add_column("Puertos", style="green", justify="right")
        table.add_column("Vulns", style="red", justify="right")
        table.add_column("Último run", style="muted")

        for target_obj in targets:
            latest_scan = get_latest_scan(db, target_obj.domain)
            status = _scan_status_from_outdir(latest_scan.out_dir if latest_scan else None)
            subdomains = db.query(Subdomain).filter(Subdomain.scan_id == latest_scan.id).all() if latest_scan else []
            ports = db.query(Port).filter(Port.scan_id == latest_scan.id).all() if latest_scan else []
            vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == latest_scan.id).all() if latest_scan else []
            table.add_row(
                target_obj.domain,
                normalize_status_label(status.get("status", latest_scan.status if latest_scan else "idle")),
                status.get("phase", "none") if latest_scan else "none",
                f"{status.get('progress', 100 if latest_scan and latest_scan.status == 'completed' else 0)}%",
                str(len(subdomains)),
                str(sum(1 for sub in subdomains if sub.is_live)),
                str(len(ports)),
                str(len(vulns)),
                latest_scan.timestamp if latest_scan and latest_scan.timestamp else "n/a",
            )

        console.print(table)


def list_known_targets() -> list[str]:
    init_db()
    with SessionLocal() as db:
        return [target.domain for target in db.query(Target).order_by(Target.added_at.desc()).all()]


def print_inspect(target: str, run: str | None = None) -> None:
    target_clean = resolve_target(target)
    if not target_clean:
        console.print(Panel("Usa: inspect <target> [run] o focus <target> primero.", title="Inspect", border_style="yellow"))
        return
    resolved_run = run
    if not resolved_run:
        latest = _latest_scan_for_target(target_clean)
        if latest and latest.out_dir:
            resolved_run = Path(latest.out_dir).name
    if not resolved_run:
        console.print(Panel(f"No hay scans para {target_clean}.", title="Inspect", border_style="yellow"))
        return

    payload = api_json(f"/scan/{quote(target_clean)}/{quote(resolved_run)}")
    if not isinstance(payload, dict):
        latest = _latest_scan_for_target(target_clean)
        scan_dir = None
        for candidate in [
            Path(latest.out_dir) if latest and latest.out_dir else None,
            ROOT_DIR / "runtime" / "scans" / target_clean / resolved_run,
            ROOT_DIR / "output" / target_clean / resolved_run,
        ]:
            if candidate and candidate.exists():
                scan_dir = candidate
                break
        if not scan_dir:
            # Si la base usa otro nombre de carpeta, buscar variantes del target.
            aliases = [target_clean]
            base_label = target_clean.split(".")[0]
            if base_label and base_label not in aliases:
                aliases.append(base_label)
            for root in [ROOT_DIR / "runtime" / "scans", ROOT_DIR / "output"]:
                for alias in aliases:
                    alias_root = root / alias
                    if not alias_root.exists():
                        continue
                    direct = alias_root / resolved_run
                    if direct.exists():
                        scan_dir = direct
                        break
                    runs = sorted((p for p in alias_root.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)
                    if runs:
                        scan_dir = runs[0]
                        resolved_run = scan_dir.name
                        break
                if scan_dir:
                    break
        if not scan_dir or not scan_dir.exists():
            console.print(Panel("No se pudo abrir el scan solicitado.", title="Inspect", border_style="red"))
            return
        data = {}
        status_file = scan_dir / "status.json"
        if status_file.exists():
            data["status"] = load_json(status_file)
        for subdir in ["recon", "ports", "crawler", "vulns", "fuzzer", "intelligence"]:
            subdir_path = scan_dir / subdir
            if subdir_path.exists():
                files = {}
                for f in sorted(subdir_path.iterdir()):
                    if f.is_file() and f.suffix == ".json":
                        files[f.name] = load_json(f)
                if files:
                    data[subdir] = files
        payload = {"target": target_clean, "run": resolved_run, "data": data}

    data = payload.get("data", {})
    status = data.get("status", {})
    console.print(Panel(f"Target: [accent]{target_clean}[/accent]\nRun: [muted]{resolved_run}[/muted]", title="Inspect", border_style="accent"))

    if isinstance(status, dict) and status:
        status_payload = {
            "target": target_clean,
            "status": status.get("status", "unknown"),
            "phase": status.get("phase", "unknown"),
            "progress": status.get("progress", 0),
            "message": status.get("message", ""),
            "error": status.get("error"),
            "updated_at": status.get("updated_at"),
            "counts": status.get("counts", {}),
        }
        console.print(_render_status_panel(status_payload, title="Estado del scan"))
        if status.get("history"):
            console.print(_render_events_table(status.get("history", []), title="Eventos del scan"))

    sections = []
    for key, value in data.items():
        if key == "status":
            continue
        if isinstance(value, dict):
            sections.append((key, len(value)))
        elif isinstance(value, list):
            sections.append((key, len(value)))
        else:
            sections.append((key, 1))

    if sections:
        table = Table(title="Secciones disponibles", box=SIMPLE_HEAVY, show_lines=False)
        table.add_column("Sección", style="accent")
        table.add_column("Elementos", style="white", justify="right")
        for name, count in sections:
            table.add_row(name, str(count))
        console.print(table)
    else:
        console.print(Panel("El scan no tiene secciones adicionales cargadas.", title="Inspect", border_style="yellow"))


def watch_status(target: str | None = None, interval: float = 2.0, max_cycles: int | None = None) -> int:
    target = resolve_target(target)
    if not target:
        latest = _latest_scan_for_target(None)
        if latest:
            target_obj = None
            with SessionLocal() as db:
                target_obj = db.query(Target).filter(Target.id == latest.target_id).first()
            target = target_obj.domain if target_obj else None
    if not target:
        console.print(Panel("No hay target disponible para seguir.", title="Watch", border_style="yellow"))
        return 1

    cycles = 0
    try:
        with Live(console=console, refresh_per_second=4) as live:
            while True:
                payload = api_json(f"/scan-status/{quote(normalize_target(target))}")
                if not isinstance(payload, dict):
                    local = get_latest_status(target)
                    payload = {
                        "target": local.get("target", normalize_target(target)),
                        "status": local.get("status", "idle"),
                        "phase": local.get("phase", "none"),
                        "progress": local.get("progress", 0),
                        "message": local.get("message", ""),
                        "error": local.get("error"),
                        "updated_at": local.get("updated_at"),
                        "events": local.get("events", []),
                        "counts": local.get("counts", {}),
                    }
                if not isinstance(payload, dict):
                    live.update(Panel("No se pudo leer el estado actual.", title="Watch", border_style="red"))
                    time.sleep(interval)
                    cycles += 1
                    continue
                renderable = Group(
                    _render_status_panel(payload, title="Watch"),
                    _render_events_table(payload.get("events", []), title="Eventos en vivo") or Panel("Sin eventos todavía.", border_style="muted"),
                )
                live.update(renderable)
                status = payload.get("status", "idle")
                if is_terminal_status(status):
                    break
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(Panel("Monitoreo detenido por el usuario.", title="Watch", border_style="yellow"))
        return 130
    return 0


def build_scan_options(
    *,
    full: bool = False,
    recon: bool = False,
    ports: bool = False,
    urls: bool = False,
    vulns: bool = False,
    report: bool = False,
    waf_detection: bool = False,
    active_fuzz: bool = False,
    threads: int = 50,
    timeout: int = 10,
    program: str | None = None,
    agent: str | None = None,
    output: str | None = None,
) -> ScanOptions:
    return ScanOptions(
        full=full,
        recon=recon,
        ports=ports,
        urls=urls,
        vulns=vulns,
        report=report,
        waf_detection=waf_detection,
        active_fuzz=active_fuzz,
        threads=threads,
        timeout=timeout,
        program=program,
        agent=agent,
        output=output,
    )


def launch_scan(target: str, opts: ScanOptions, *, background: bool = False) -> subprocess.Popen | int:
    cmd = build_scan_command(target, opts)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    if background:
        return subprocess.Popen(
            cmd,
            cwd=str(ROOT_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            console.print(line.rstrip())
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        console.print("[warn]Scan cancelado por el usuario.[/warn]")
        return 130


def parse_scan_tokens(tokens: list[str]) -> tuple[str, ScanOptions]:
    parser = argparse.ArgumentParser(prog="scan", add_help=False)
    parser.add_argument("target")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--recon", action="store_true")
    parser.add_argument("--ports", action="store_true")
    parser.add_argument("--urls", action="store_true")
    parser.add_argument("--vulns", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--waf-detection", action="store_true")
    parser.add_argument("--active-fuzz", action="store_true")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("-p", "--program")
    parser.add_argument("--agent")
    parser.add_argument("-o", "--output")
    args = parser.parse_args(tokens)
    opts = build_scan_options(
        full=args.full,
        recon=args.recon,
        ports=args.ports,
        urls=args.urls,
        vulns=args.vulns,
        report=args.report,
        waf_detection=args.waf_detection,
        active_fuzz=args.active_fuzz,
        threads=args.threads,
        timeout=args.timeout,
        program=args.program,
        agent=args.agent,
        output=args.output,
    )
    return args.target, opts


def recent_runs(limit: int = 3) -> list[dict]:
    return get_history(limit=limit)
