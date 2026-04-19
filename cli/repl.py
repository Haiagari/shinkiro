from __future__ import annotations

import cmd
import readline
import shlex
import threading
from pathlib import Path

from rich.panel import Panel

from . import commands
from ui.renderer import console
from ui.welcome import print_welcome


HISTORY_FILE = Path.home() / ".bugbounty-cli" / "history"


class AgentShell(cmd.Cmd):
    intro = None
    prompt = "\033[38;5;208m❯\033[0m "

    def __init__(self, username: str, api_base: str, api_ok: bool, recent: list[dict] | None = None):
        super().__init__()
        self.username = username
        self.api_base = api_base
        self.api_ok = api_ok
        self.recent = recent or []
        self.active_proc = None
        self.active_target = None
        self._printer_threads: list[threading.Thread] = []

    def _target_suggestions(self) -> list[str]:
        targets = []
        for item in commands.list_known_targets():
            if item not in targets:
                targets.append(item)
        for item in self.recent:
            target = item.get("target")
            if target and target not in targets:
                targets.append(target)
        return targets

    def preloop(self):
        print_welcome(
            username=self.username,
            api_base=self.api_base,
            api_ok=self.api_ok,
            mode="INTERACTIVE",
            recent=self.recent,
        )

    def precmd(self, line: str) -> str:
        line = line.strip()
        if line.startswith("/"):
            return line[1:]
        return line

    def emptyline(self):
        return False

    def default(self, line: str):
        try:
            cmd_name, *rest = shlex.split(line)
        except ValueError as exc:
            console.print(f"[fail]Parse error:[/] {exc}")
            return

        handlers = {
            "scan": self.do_scan,
            "status": self.do_status,
            "history": self.do_history,
            "report": self.do_report,
            "overview": self.do_overview,
            "targets": self.do_targets,
            "inspect": self.do_inspect,
            "watch": self.do_watch,
            "focus": self.do_focus,
            "diff": self.do_diff,
            "export": self.do_export,
            "doctor": self.do_doctor,
            "abort": self.do_abort,
            "help": self.do_help,
            "exit": self.do_exit,
            "quit": self.do_quit,
        }

        handler = handlers.get(cmd_name.lower())
        if handler:
            handler(" ".join(rest))
            return

        console.print(Panel(f"Comando desconocido: [accent]{cmd_name}[/accent]\nEscribe [cmd]help[/cmd] para ver opciones.", border_style="red"))

    def complete_scan(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_status(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_history(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_report(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_overview(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_inspect(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def complete_watch(self, text: str, line: str, begidx: int, endidx: int):
        return [t for t in self._target_suggestions() if t.startswith(text)]

    def do_scan(self, arg: str):
        try:
            target, opts = commands.parse_scan_tokens(shlex.split(arg))
        except SystemExit:
            return

        if self.active_proc and self.active_proc.poll() is None:
            console.print(Panel("Ya hay un scan corriendo. Usa [cmd]abort[/cmd] si quieres cancelarlo.", border_style="yellow"))
            return

        proc = commands.launch_scan(target, opts, background=True)
        self.active_proc = proc
        self.active_target = commands.normalize_target(target)

        console.print(
            Panel(
                f"Target: [bold]{self.active_target}[/bold]\nModo: [bold]{opts.agent or ('FULL' if opts.full else 'STANDARD')}[/bold]\nPID: [bold]{proc.pid}[/bold]",
                title="Scan lanzado",
                border_style="green",
            )
        )

        def _pump():
            assert proc.stdout is not None
            for line in proc.stdout:
                console.print(line.rstrip())
            rc = proc.wait()
            console.print(
                Panel(
                    f"Proceso finalizado con código {rc}",
                    title="Scan terminado",
                    border_style="green" if rc == 0 else "red",
                )
            )
            if self.active_proc is proc:
                self.active_proc = None
                self.active_target = None

        thread = threading.Thread(target=_pump, daemon=True)
        thread.start()
        self._printer_threads.append(thread)

    def do_status(self, arg: str):
        target = arg.strip() or None
        commands.print_status(target)

    def do_history(self, arg: str):
        target = arg.strip() or None
        commands.print_history(target, limit=10)

    def do_report(self, arg: str):
        target = arg.strip() or None
        commands.print_report(target)

    def do_overview(self, arg: str):
        target = arg.strip() or None
        commands.print_overview(target)

    def do_targets(self, arg: str):
        commands.print_targets()

    def do_inspect(self, arg: str):
        try:
            tokens = shlex.split(arg)
        except ValueError as exc:
            console.print(f"[fail]Parse error:[/] {exc}")
            return
        target = tokens[0] if tokens else commands.get_focused_target()
        if not target:
            console.print(Panel("Uso: inspect <target> [run] o focus <target> primero.", border_style="yellow"))
            return
        run = tokens[1] if len(tokens) > 1 else None
        commands.print_inspect(target, run)

    def do_watch(self, arg: str):
        try:
            tokens = shlex.split(arg)
        except ValueError as exc:
            console.print(f"[fail]Parse error:[/] {exc}")
            return
        target = None
        interval = 2.0
        max_cycles = None
        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            if token in {"-i", "--interval"} and idx + 1 < len(tokens):
                try:
                    interval = float(tokens[idx + 1])
                except ValueError:
                    interval = 2.0
                idx += 2
                continue
            if token in {"-n", "--count"} and idx + 1 < len(tokens):
                try:
                    max_cycles = int(tokens[idx + 1])
                except ValueError:
                    max_cycles = None
                idx += 2
                continue
            if not target:
                target = token
            idx += 1
        commands.watch_status(target, interval=interval, max_cycles=max_cycles)

    def do_focus(self, arg: str):
        target = arg.strip() or None
        commands.focus_target(target)

    def do_diff(self, arg: str):
        target = arg.strip() or None
        commands.print_diff(target)

    def do_export(self, arg: str):
        try:
            tokens = shlex.split(arg)
        except ValueError as exc:
            console.print(f"[fail]Parse error:[/] {exc}")
            return
        target = None
        fmt = "json"
        output = None
        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            if token in {"-f", "--format"} and idx + 1 < len(tokens):
                fmt = tokens[idx + 1]
                idx += 2
                continue
            if token in {"-o", "--output"} and idx + 1 < len(tokens):
                output = tokens[idx + 1]
                idx += 2
                continue
            if not target:
                target = token
            idx += 1
        commands.export_summary(target, fmt=fmt, output=output)

    def do_doctor(self, arg: str):
        commands.print_doctor()

    def do_abort(self, arg: str):
        if not self.active_proc or self.active_proc.poll() is not None:
            console.print(Panel("No hay ningún scan activo.", border_style="yellow"))
            return
        self.active_proc.terminate()
        console.print(Panel("Scan abortado.", border_style="red"))

    def do_help(self, arg: str):
        table = Panel(
            "\n".join(
                [
                    "[accent]scan <target> [opts][/accent]  Lanzar scan real",
                    "[accent]status [target][/accent]        Ver estado más reciente",
                    "[accent]history [target][/accent]       Ver historial local",
                    "[accent]report [target][/accent]        Resumen del último scan",
                    "[accent]overview [target][/accent]      Resumen del comando",
                    "[accent]targets[/accent]               Targets monitoreados",
                    "[accent]inspect <target> [run][/accent]  Ver un run concreto",
                    "[accent]watch [target][/accent]         Seguimiento en vivo",
                    "[accent]focus [target][/accent]         Fijar target activo",
                    "[accent]diff [target][/accent]          Comparar run actual",
                    "[accent]export [target][/accent]        Exportar resumen",
                    "[accent]doctor[/accent]                 Diagnóstico del entorno",
                    "[accent]abort[/accent]                  Cerrar scan activo",
                    "[accent]exit|quit[/accent]             Salir",
                    "[accent]/help[/accent] y slash commands      Atajos estilo Claude Code",
                ]
            ),
            title="Comandos",
            border_style="cyan",
        )
        console.print(table)

    def do_exit(self, arg: str):
        return True

    def do_quit(self, arg: str):
        return True

    def do_EOF(self, arg: str):
        console.print()
        return True


def run_repl(username: str, api_base: str, api_ok: bool, recent: list[dict] | None = None):
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        readline.read_history_file(str(HISTORY_FILE))
    except FileNotFoundError:
        pass
    except OSError:
        pass
    try:
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass

    shell = AgentShell(username=username, api_base=api_base, api_ok=api_ok, recent=recent)
    try:
        shell.cmdloop()
    finally:
        try:
            readline.write_history_file(str(HISTORY_FILE))
        except OSError:
            pass
