from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import commands
from .tui import run_tui


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ozy",
        description="OzyRecon CLI - Offensive Reconnaissance Platform",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command")

    # Modos operativos
    hunt = sub.add_parser("hunt", help="Modo HUNT - Caza agresiva en targets nuevos")
    hunt.add_argument("-t", "--target", required=True, help="Dominio objetivo")
    hunt.add_argument("--threads", type=int, default=50)
    hunt.add_argument("--rate-limit", type=int, default=200)
    hunt.add_argument("--dry-run", action="store_true")

    continuous = sub.add_parser("continuous", help="Modo CONTINUO - Monitoreo 24/7")
    continuous.add_argument("-t", "--target", required=True)
    continuous.add_argument("--interval", type=int, default=3600)

    campaign = sub.add_parser("campaign", help="Modo CAMPAÑA - Escalado de patrones")
    campaign.add_argument("-p", "--pattern", required=True, help="CVE-ID o template")
    campaign.add_argument("-t", "--targets", nargs="+", help="Lista de targets")

    research = sub.add_parser("research", help="Modo INVESTIGACIÓN - Búsqueda de CVEs")
    research.add_argument("-t", "--target", required=True)
    research.add_argument("--cve", help="CVE específico")

    forensic = sub.add_parser("forensic", help="Modo FORENSE - Análisis post-mortem")
    forensic.add_argument("-t", "--target", required=True)

    servicio = sub.add_parser("servicio", help="Modo SERVICIO - Reportes ejecutivos")
    servicio.add_argument("-t", "--target", required=True)
    servicio.add_argument("--client", help="Nombre del cliente")

    # Comandos Legacy
    scan = sub.add_parser("scan", help="Lanza un scan (compatibilidad)")
    scan.add_argument("target", help="Dominio objetivo")
    scan.add_argument("--full", action="store_true")
    scan.add_argument("--recon", action="store_true")
    scan.add_argument("--ports", action="store_true")
    scan.add_argument("--urls", action="store_true")
    scan.add_argument("--vulns", action="store_true")
    scan.add_argument("--report", action="store_true")
    scan.add_argument("--waf-detection", action="store_true")
    scan.add_argument("--active-fuzz", action="store_true")
    scan.add_argument("--threads", type=int, default=50)
    scan.add_argument("--timeout", type=int, default=10)
    scan.add_argument("-p", "--program")
    scan.add_argument("--agent")
    scan.add_argument("-o", "--output")

    status = sub.add_parser("status", help="Ver el último estado")
    status.add_argument("target", nargs="?", default=None)

    history = sub.add_parser("history", help="Ver historial local")
    history.add_argument("target", nargs="?", default=None)
    history.add_argument("-n", "--limit", type=int, default=10)

    report = sub.add_parser("report", help="Resumen del último scan")
    report.add_argument("target", nargs="?", default=None)

    overview = sub.add_parser("overview", help="Resumen operativo del framework")
    overview.add_argument("target", nargs="?", default=None)

    targets = sub.add_parser("targets", help="Listar targets monitoreados")

    inspect = sub.add_parser("inspect", help="Abrir un scan concreto")
    inspect.add_argument("target", help="Dominio objetivo")
    inspect.add_argument("run", nargs="?", default=None)

    watch = sub.add_parser("watch", help="Seguir un scan en vivo")
    watch.add_argument("target", nargs="?", default=None)
    watch.add_argument("-i", "--interval", type=float, default=2.0)
    watch.add_argument("-n", "--count", type=int, default=None)

    focus = sub.add_parser("focus", help="Fijar target activo")
    focus.add_argument("target", nargs="?", default=None)

    diff = sub.add_parser("diff", help="Comparar el último scan con el anterior")
    diff.add_argument("target", nargs="?", default=None)

    export = sub.add_parser("export", help="Exportar resumen")
    export.add_argument("target", nargs="?", default=None)
    export.add_argument("--format", choices=["json", "md"], default="json")
    export.add_argument("-o", "--output")

    sub.add_parser("doctor", help="Diagnóstico del entorno")
    sub.add_parser("shell", help="Abrir la shell interactiva")

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        user = getpass.getuser()
        recent = commands.recent_runs(3)
        run_tui(user, commands.API_BASE, commands.api_alive(), recent=recent)
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None or args.command == "shell":
        user = getpass.getuser()
        recent = commands.recent_runs(3)
        run_tui(user, commands.API_BASE, commands.api_alive(), recent=recent)
        return 0

    if args.command == "scan":
        opts = commands.build_scan_options(
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
        return int(commands.launch_scan(args.target, opts, background=False))

    if args.command == "status":
        commands.print_status(args.target)
        return 0

    if args.command == "history":
        commands.print_history(args.target, limit=args.limit)
        return 0

    if args.command == "report":
        commands.print_report(args.target)
        return 0

    if args.command == "overview":
        commands.print_overview(args.target)
        return 0

    if args.command == "targets":
        commands.print_targets()
        return 0

    if args.command == "inspect":
        commands.print_inspect(args.target, args.run)
        return 0

    if args.command == "watch":
        return int(commands.watch_status(args.target, interval=args.interval, max_cycles=args.count))

    if args.command == "focus":
        commands.focus_target(args.target)
        return 0

    if args.command == "diff":
        commands.print_diff(args.target)
        return 0

    if args.command == "export":
        commands.export_summary(args.target, fmt=args.format, output=args.output)
        return 0

    if args.command == "doctor":
        commands.print_doctor()
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
