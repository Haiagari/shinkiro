from __future__ import annotations

import json
import os
import shlex
import threading
import time
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from prompt_toolkit.application import Application
from prompt_toolkit.application.current import get_app_or_none
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Dimension, HSplit, Layout
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import TextArea

from . import commands


SPINNER_FRAMES = ["✱", "✦", "✧", "✹"]
MAX_ITEMS = 400


@dataclass
class ConversationItem:
    kind: str
    text: str = ""
    title: str = ""
    desc: str = ""
    state: str = "done"
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


class CommandCompleter(Completer):
    def __init__(self, tui: "ClaudeLikeTUI"):
        self.tui = tui
        self.commands = [
            "scan",
            "status",
            "history",
            "report",
            "overview",
            "targets",
            "inspect",
            "watch",
            "focus",
            "diff",
            "export",
            "doctor",
            "abort",
            "clear",
            "recent",
            "help",
            "exit",
            "quit",
        ]

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()
        parts = text.split()
        if len(parts) <= 1 and not text.endswith(" "):
            needle = parts[0].lower() if parts else ""
            for item in self.commands:
                if item.startswith(needle):
                    yield Completion(item, start_position=-len(needle))
            return

        if not parts:
            return

        cmd = parts[0].lower()
        current = parts[-1] if not text.endswith(" ") else ""
        if cmd in {"scan", "status", "history", "report", "overview", "inspect", "watch", "focus", "diff", "export"}:
            for target in self.tui._target_suggestions():
                if target.startswith(current):
                    yield Completion(target, start_position=-len(current))


class ClaudeLikeTUI:
    def __init__(self, username: str, api_base: str, api_ok: bool, recent: list[dict] | None = None):
        self.username = username
        self.api_base = api_base
        self.api_ok = api_ok
        self.recent = recent or []
        self.items: list[ConversationItem] = []
        self._lock = threading.RLock()
        self._active_proc = None
        self._active_task: ConversationItem | None = None
        self._spinner_running = False
        self._spinner_thread: threading.Thread | None = None
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._app: Application | None = None
        self.follow_tail = True
        self.history = InMemoryHistory()
        self._build_ui()

    def _target_suggestions(self) -> list[str]:
        items: list[str] = []
        focused = commands.get_focused_target()
        if focused:
            items.append(focused)
        for item in commands.list_known_targets():
            if item and item not in items:
                items.append(item)
        for item in self.recent:
            target = item.get("target")
            if target and target not in items:
                items.append(target)
        return items[:50]

    def _build_ui(self) -> None:
        self.header_area = TextArea(
            text=self._render_header_text(),
            read_only=True,
            focusable=False,
            multiline=True,
            wrap_lines=False,
            scrollbar=False,
            height=7,
            style="class:header",
        )
        self.output_area = TextArea(
            text=self._render_output_text(),
            read_only=True,
            focusable=False,
            multiline=True,
            wrap_lines=True,
            scrollbar=True,
            style="class:conversation",
            height=Dimension(weight=1),
            dont_extend_height=False,
        )
        self.status_area = TextArea(
            text=self._render_status_line(),
            read_only=True,
            focusable=False,
            multiline=False,
            wrap_lines=False,
            scrollbar=False,
            height=1,
            style="class:statusline",
        )
        self.prompt_area = TextArea(
            text="",
            multiline=False,
            wrap_lines=False,
            accept_handler=self._on_submit,
            completer=CommandCompleter(self),
            complete_while_typing=True,
            focusable=True,
            focus_on_click=True,
            scrollbar=False,
            height=1,
            style="class:prompt-area",
            prompt="❯ ",
            history=self.history,
        )

        root = HSplit([self.header_area, self.output_area, self.status_area, self.prompt_area])

        self.kb = KeyBindings()

        @self.kb.add("c-c")
        def _(event) -> None:
            if self._active_proc and self._active_proc.poll() is None:
                self.abort_active()
                return
            self._shutdown()
            event.app.exit()

        @self.kb.add("c-d")
        def _(event) -> None:
            self._shutdown()
            event.app.exit()

        @self.kb.add("c-l")
        def _(event) -> None:
            self._clear_output()

        @self.kb.add("f5")
        def _(event) -> None:
            self._append_bullet("Refrescando vista…")
            self._invalidate()

        @self.kb.add("escape")
        def _(event) -> None:
            if self._active_proc and self._active_proc.poll() is None:
                self.abort_active()
                return
            if self._watch_thread and self._watch_thread.is_alive():
                self._watch_stop.set()
                self._append_result("Seguimiento detenido.")
                self._invalidate()
                return
            if not self.follow_tail:
                self.follow_tail = True
                self._scroll_to_bottom()
                self._invalidate()

        @self.kb.add("pageup")
        def _(event) -> None:
            self.follow_tail = False
            try:
                self.output_area.window.vertical_scroll = max(0, self.output_area.window.vertical_scroll - 6)
            except Exception:
                pass
            self._invalidate()

        @self.kb.add("pagedown")
        def _(event) -> None:
            try:
                self.output_area.window.vertical_scroll = max(0, self.output_area.window.vertical_scroll + 6)
                if self.output_area.window.vertical_scroll > 0:
                    self.follow_tail = False
            except Exception:
                pass
            self._invalidate()

        @self.kb.add("home")
        def _(event) -> None:
            self.follow_tail = False
            try:
                self.output_area.window.vertical_scroll = 0
            except Exception:
                pass
            self._invalidate()

        @self.kb.add("end")
        def _(event) -> None:
            self.follow_tail = True
            self._scroll_to_bottom()
            self._invalidate()

        style = Style.from_dict(
            {
                "root": "bg:#0b0d10 #d1d5db",
                "header": "bg:#0b0d10 #e5e7eb",
                "conversation": "bg:#0b0d10 #d1d5db",
                "statusline": "bg:#111316 #9ca3af",
                "prompt-area": "bg:#0b0d10 #e5e7eb",
            }
        )

        self._app = Application(
            layout=Layout(root, focused_element=self.prompt_area),
            key_bindings=self.kb,
            style=style,
            full_screen=True,
            mouse_support=True,
        )
        try:
            self._app.pre_run_callables.append(lambda: self._app and self._app.layout.focus(self.prompt_area))
        except Exception:
            pass

    def _render_header_text(self) -> str:
        focused = commands.get_focused_target() or "n/a"
        cwd = Path.cwd()
        api_label = "online" if self.api_ok else "offline"
        active = "running" if self._active_proc and self._active_proc.poll() is None else "idle"
        watch = "on" if self._watch_thread and self._watch_thread.is_alive() and not self._watch_stop.is_set() else "off"
        return "\n".join(
            [
                "    ___,   BUG BOUNTY CLI v0.2.0",
                '   [O.O]   "Nunca confíes, siempre verifica."',
                f"   /)__)   user: {self.username}",
                f'   -"--"-   api: {self.api_base} [{api_label}]',
                f"           focused: {focused}",
                f"           proc: {active} · watch: {watch} · tail: {'on' if self.follow_tail else 'off'}",
                f"           cwd: {cwd}",
            ]
        )

    def _render_status_line(self) -> str:
        hints = "Tab completar · PgUp/PgDn navegar · End seguir tail · Esc abortar/parar · Ctrl+L limpiar · Ctrl+D salir"
        if self._active_task and self._active_task.state == "running":
            status = self._active_task.metrics.get("status_text", self._active_task.title or "working")
            return f" {status} │ {hints}"
        return f" listo │ {hints}"

    def _term_width(self) -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 100

    def _wrap_lines(self, text: str, width: int) -> list[str]:
        import textwrap

        if text == "":
            return [""]
        lines: list[str] = []
        for line in text.splitlines() or [""]:
            wrapped = textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False)
            lines.extend(wrapped or [""])
        return lines

    def _render_item_text(self, item: ConversationItem) -> str:
        if item.kind == "user":
            width = max(48, min(120, self._term_width() - 2))
            sep = "─" * width
            return "\n".join([sep, f"  ❯ {item.text}", sep])
        if item.kind == "bullet":
            return f"• {item.text}"
        if item.kind == "tool":
            title = item.title or "Tool"
            desc = item.desc or ""
            lines = [f"• {title}({desc})" if desc else f"• {title}"]
            if desc:
                lines = [f"• {title}({desc})"]
            if item.state == "running":
                spinner = SPINNER_FRAMES[int(time.time() * 8) % len(SPINNER_FRAMES)]
                status = item.metrics.get("status_text", "Working…")
                extra = []
                progress = item.metrics.get("progress")
                phase = item.metrics.get("phase")
                if phase:
                    extra.append(f"phase={phase}")
                if progress is not None:
                    extra.append(f"progress={progress}%")
                suffix = f" [{' · '.join(extra)}]" if extra else ""
                lines.append(f"    └ {spinner} {status}{suffix} (esc to interrupt)")
            elif item.state == "error":
                lines.append(f"    └ Error: {item.metrics.get('error', 'unknown')}")
            else:
                metrics = item.metrics
                findings = metrics.get("findings")
                duration = metrics.get("duration", 0.0)
                if findings is not None:
                    lines.append(f"    └ Done  ({findings} findings · {duration:.1f}s)")
                else:
                    lines.append(f"    └ Done  ({duration:.1f}s)")
            return "\n".join(lines)
        if item.kind == "code":
            code_lines = item.text.splitlines() or [""]
            width = max(48, min(120, self._term_width() - 2))
            top = f"┌─ {item.title or item.metrics.get('file', 'code')} " + "─" * max(1, width - len(item.title or item.metrics.get('file', 'code')) - 4)
            bottom = "└" + "─" * (width - 2)
            numbered = []
            start_line = int(item.metrics.get("start_line", 1))
            highlight = item.metrics.get("highlight")
            for idx, line in enumerate(code_lines, start=start_line):
                prefix = "▶ " if highlight is not None and idx == highlight else "  "
                numbered.append(f"{prefix}{idx:>3} │ {line}")
            return "\n".join([top, *numbered, bottom])
        if item.kind == "result":
            return "\n".join(f"  {line}" for line in (item.text.splitlines() or [""]))
        if item.kind == "system":
            return f" ✱ {item.text}"
        return "\n".join(f"  {line}" for line in (item.text.splitlines() or [""]))

    def _render_output_text(self) -> str:
        with self._lock:
            items = list(self.items)
        if not items:
            width = max(48, min(120, self._term_width() - 2))
            sep = "─" * width
            return "\n".join([sep, "  • Escribe help para ver los comandos disponibles.", sep])
        return "\n\n".join(self._render_item_text(item) for item in items)

    def _invalidate(self) -> None:
        if self.follow_tail:
            self._scroll_to_bottom()
        try:
            self.header_area.text = self._render_header_text()
            self.output_area.text = self._render_output_text()
            self.status_area.text = self._render_status_line()
        except Exception:
            pass
        app = self._app or get_app_or_none()
        if app is not None:
            app.invalidate()

    def _scroll_to_bottom(self) -> None:
        try:
            self.output_area.buffer.cursor_position = len(self.output_area.buffer.text)
        except Exception:
            pass
        try:
            self.output_area.window.vertical_scroll = 10**9
        except Exception:
            pass

    def _trim_items(self) -> None:
        if len(self.items) > MAX_ITEMS:
            del self.items[: len(self.items) - MAX_ITEMS]

    def _push(self, item: ConversationItem) -> ConversationItem:
        with self._lock:
            self.items.append(item)
            self._trim_items()
        if self.follow_tail:
            self._scroll_to_bottom()
        self._invalidate()
        return item

    def _clear_output(self) -> None:
        with self._lock:
            self.items.clear()
        self._append_bullet("Salida limpiada.")

    def _append_user(self, text: str) -> None:
        self._push(ConversationItem(kind="user", text=text))

    def _append_bullet(self, text: str) -> None:
        self._push(ConversationItem(kind="bullet", text=text))

    def _append_result(self, text: str) -> None:
        self._push(ConversationItem(kind="result", text=text))

    def _append_code(self, text: str) -> None:
        self._push(ConversationItem(kind="code", text=text))

    def _append_json(self, payload: Any) -> None:
        self._append_code(json.dumps(payload, indent=2, ensure_ascii=False))

    def _start_tool(self, title: str, desc: str, status_text: str = "Working…") -> ConversationItem:
        tool = self._push(
            ConversationItem(
                kind="tool",
                title=title,
                desc=desc,
                state="running",
                metrics={"status_text": status_text},
            )
        )
        self._active_task = tool
        self._ensure_spinner()
        return tool

    def _finish_tool(self, tool: ConversationItem, *, findings: int | None = None, duration: float = 0.0, error: str | None = None) -> None:
        with self._lock:
            tool.state = "error" if error else "done"
            tool.metrics.pop("status_text", None)
            tool.metrics["duration"] = duration
            if findings is not None:
                tool.metrics["findings"] = findings
            if error:
                tool.metrics["error"] = error
        self._active_task = None
        self._invalidate()

    def _ensure_spinner(self) -> None:
        if self._spinner_running:
            return
        self._spinner_running = True

        def _loop() -> None:
            while self._spinner_running:
                self._invalidate()
                time.sleep(0.08)

        self._spinner_thread = threading.Thread(target=_loop, daemon=True)
        self._spinner_thread.start()

    def _stop_spinner(self) -> None:
        self._spinner_running = False

    def _shutdown(self) -> None:
        self._watch_stop.set()
        self._stop_spinner()

    def _run_safe(self, handler: Callable[[list[str]], None], args: list[str]) -> None:
        try:
            handler(args)
        except KeyboardInterrupt:
            self._append_result("Operación interrumpida.")
        except Exception as exc:
            self._append_result(f"Error: {exc}")

    def _on_submit(self, buff: Buffer) -> None:
        text = buff.text.strip()
        buff.reset()
        if not text:
            self._invalidate()
            return

        if text.startswith("/"):
            text = text[1:]

        self._append_user(text)

        try:
            tokens = shlex.split(text)
        except ValueError as exc:
            self._append_result(f"Parse error: {exc}")
            self._invalidate()
            return

        if not tokens:
            return

        cmd = tokens[0].lower()
        args = tokens[1:]
        handlers: dict[str, Callable[[list[str]], None]] = {
            "scan": self._cmd_scan,
            "status": self._cmd_status,
            "history": self._cmd_history,
            "report": self._cmd_report,
            "overview": self._cmd_overview,
            "targets": self._cmd_targets,
            "inspect": self._cmd_inspect,
            "watch": self._cmd_watch,
            "focus": self._cmd_focus,
            "diff": self._cmd_diff,
            "export": self._cmd_export,
            "doctor": self._cmd_doctor,
            "abort": self._cmd_abort,
            "clear": self._cmd_clear,
            "recent": self._cmd_recent,
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }
        handler = handlers.get(cmd)
        if not handler:
            self._append_result(f"Comando desconocido: {cmd}. Escribe help.")
            return
        self._run_safe(handler, args)

    def _cmd_help(self, args: list[str]) -> None:
        self._append_bullet("Comandos disponibles")
        for line in [
            "scan <target> [opts]   lanzar scan real",
            "status [target]        ver estado más reciente",
            "history [target]       ver historial local",
            "report [target]        resumen del último scan",
            "overview [target]      resumen operativo",
            "targets                targets monitoreados",
            "inspect <target> [run] ver un run concreto",
            "watch [target]         seguimiento en vivo",
            "focus <target>         fijar target activo",
            "diff [target]          comparar último scan",
            "export [target]        exportar resumen",
            "doctor                 diagnóstico del entorno",
            "recent                 mostrar recientes en el header",
            "clear                  limpiar conversación",
            "abort                  cerrar scan activo o watch",
            "exit|quit              salir",
        ]:
            self._append_result(f"  {line}")

    def _cmd_exit(self, args: list[str]) -> None:
        self._shutdown()
        if self._app:
            self._app.exit()

    def abort_active(self) -> None:
        self._cmd_abort([])

    def _cmd_clear(self, args: list[str]) -> None:
        self._clear_output()

    def _cmd_recent(self, args: list[str]) -> None:
        if not self.recent:
            self._append_result("No hay actividad reciente.")
            return
        self._append_bullet("Actividad reciente")
        for item in self.recent[-5:]:
            self._append_result(
                f"• {item.get('target', 'n/a')} · {commands.normalize_status_label(item.get('status'))} · run #{item.get('scan_id', 'n/a')}"
            )

    def _cmd_focus(self, args: list[str]) -> None:
        target = args[0] if args else None
        focused = commands.set_focused_target(target) if target else commands.get_focused_target()
        if not focused:
            self._append_result("Usa focus <target>.")
            return
        self._append_bullet(f"Target activo fijado en {focused}")
        current = commands.get_latest_status(focused)
        self._append_result(f"• Estado: {commands.normalize_status_label(current.get('status'))}")
        self._append_result(f"• Fase: {current.get('phase', 'none')}")
        self._append_result(f"• Progreso: {current.get('progress', 0)}%")

    def _cmd_status(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        payload = commands.get_latest_status(target)
        self._append_bullet(f"Estado de {payload.get('target', target or 'latest')}")
        self._append_result(f"• Estado: {commands.normalize_status_label(payload.get('status'))}")
        self._append_result(f"• Fase: {payload.get('phase', 'none')}")
        self._append_result(f"• Progreso: {payload.get('progress', 0)}%")
        self._append_result(f"• Mensaje: {payload.get('message') or '—'}")
        if payload.get("counts"):
            counts = payload["counts"]
            self._append_result(
                f"• Conteos: {counts.get('subdomains', 0)} subs · {counts.get('live_hosts', 0)} hosts · {counts.get('ports', 0)} puertos · {counts.get('vulns', 0)} vulns"
            )

    def _cmd_history(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        items = commands.get_history(target, limit=8)
        self._append_bullet(f"Historial {target or 'global'}")
        if not items:
            self._append_result("Sin historial.")
            return
        for item in items[:8]:
            self._append_result(
                f"• #{item.get('scan_id', '')} {item.get('target', 'n/a')} · {commands.normalize_status_label(item.get('status'))} · {item.get('progress', 0)}%"
            )

    def _cmd_report(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        payload = commands.get_latest_status(target)
        counts = payload.get("counts", {})
        self._append_bullet(f"Reporte de {payload.get('target', target or 'latest')}")
        self._append_result(f"• Subdominios: {counts.get('subdomains', 0)}")
        self._append_result(f"• Hosts vivos: {counts.get('live_hosts', 0)}")
        self._append_result(f"• Puertos: {counts.get('ports', 0)}")
        self._append_result(f"• Vulns: {counts.get('vulns', 0)}")
        self._append_result(f"• Críticos: {counts.get('critical', 0)} · Altos: {counts.get('high', 0)} · Medios: {counts.get('medium', 0)}")

    def _cmd_overview(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        tool = self._start_tool("Overview", target or "latest", "Reading framework state…")
        started = time.time()
        payload = commands.build_export_payload(target)
        if not payload:
            self._finish_tool(tool, error="no data", duration=time.time() - started)
            self._append_result("No se pudo leer el estado del framework.")
            return
        project = payload.get("project", {})
        stats = payload.get("stats", {})
        scan_status = payload.get("scan_status", {})
        findings = payload.get("findings", [])
        self._append_bullet(f"{project.get('name', 'BugBounty Framework')} · {project.get('target', 'n/a')}")
        self._append_result(f"• Run: {project.get('run', 'n/a')}")
        self._append_result(f"• Estado: {commands.normalize_status_label(project.get('status'))}")
        self._append_result(
            f"• Resumen: {stats.get('subdomains', 0)} subs · {stats.get('hosts', 0)} hosts · {stats.get('ports', 0)} puertos"
        )
        self._append_result(f"• Steps: {stats.get('steps', 0)} · Score: {stats.get('score', 0)}")
        self._append_result(f"• Hallazgos: {len(findings)}")
        self._append_result(f"• Progreso: {scan_status.get('progress', 0)}%")
        self._finish_tool(tool, findings=len(findings), duration=time.time() - started)

    def _cmd_targets(self, args: list[str]) -> None:
        started = time.time()
        tool = self._start_tool("Targets", "monitored", "Loading targets…")
        lines = commands.list_known_targets()
        self._append_bullet("Targets monitoreados")
        if not lines:
            self._append_result("Sin targets conocidos.")
        for line in lines:
            self._append_result(f"• {line}")
        self._finish_tool(tool, duration=time.time() - started)

    def _cmd_inspect(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        run = args[1] if len(args) > 1 else None
        if not target:
            self._append_result("Usa inspect <target> [run] o focus <target> primero.")
            return
        started = time.time()
        tool = self._start_tool("Inspect", target, "Opening scan details…")
        resolved = run
        if not resolved:
            latest = commands._latest_scan_for_target(target)
            if latest and latest.out_dir:
                resolved = Path(latest.out_dir).name
        if not resolved:
            self._finish_tool(tool, error="no scan", duration=time.time() - started)
            self._append_result(f"No hay scans para {target}.")
            return
        payload = commands.api_json(f"/scan/{target}/{resolved}")
        if not isinstance(payload, dict):
            self._finish_tool(tool, error="offline", duration=time.time() - started)
            self._append_result(f"No se pudo abrir el scan {target}/{resolved}.")
            return
        data = payload.get("data", {})
        status = data.get("status", {})
        self._append_bullet(f"Inspect {target} · run {resolved}")
        if status:
            self._append_result(f"• Estado: {commands.normalize_status_label(status.get('status'))}")
            self._append_result(f"• Fase: {status.get('phase', 'unknown')}")
            self._append_result(f"• Progreso: {status.get('progress', 0)}%")
        for sec, value in data.items():
            if sec == "status":
                continue
            count = len(value) if isinstance(value, (list, dict)) else 1
            self._append_result(f"• {sec}: {count}")
        self._finish_tool(tool, duration=time.time() - started)

    def _cmd_watch(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        if not target:
            self._append_result("Usa watch <target> o focus <target> primero.")
            return
        if self._watch_thread and self._watch_thread.is_alive():
            self._append_result("Ya hay un watch activo. Usa abort o Esc para detenerlo.")
            return
        interval = 2.0
        count = None
        idx = 1 if args else 0
        while idx < len(args):
            token = args[idx]
            if token in {"-i", "--interval"} and idx + 1 < len(args):
                try:
                    interval = float(args[idx + 1])
                except ValueError:
                    interval = 2.0
                idx += 2
                continue
            if token in {"-n", "--count"} and idx + 1 < len(args):
                try:
                    count = int(args[idx + 1])
                except ValueError:
                    count = None
                idx += 2
                continue
            idx += 1

        tool = self._start_tool("Watch", target, "Watching live scan…")
        self._watch_stop.clear()
        started = time.time()

        def _worker() -> None:
            cycles = 0
            try:
                while not self._watch_stop.is_set():
                    payload = commands.get_latest_status(target)
                    with self._lock:
                        tool.metrics["status_text"] = f"{commands.normalize_status_label(payload.get('status'))} · {payload.get('progress', 0)}%"
                        tool.metrics["progress"] = payload.get("progress", 0)
                        tool.metrics["phase"] = payload.get("phase", "none")
                    self._invalidate()
                    if commands.is_terminal_status(payload.get("status")):
                        break
                    cycles += 1
                    if count is not None and cycles >= count:
                        break
                    time.sleep(interval)
                payload = commands.get_latest_status(target)
                self._finish_tool(
                    tool,
                    duration=time.time() - started,
                    findings=payload.get("counts", {}).get("vulns", 0) if isinstance(payload.get("counts"), dict) else None,
                )
                self._append_result(
                    f"Watch finalizado: {commands.normalize_status_label(payload.get('status'))} · {payload.get('progress', 0)}%"
                )
            except Exception as exc:
                self._finish_tool(tool, error=str(exc), duration=time.time() - started)
                self._append_result(f"Watch error: {exc}")

        self._watch_thread = threading.Thread(target=_worker, daemon=True)
        self._watch_thread.start()

    def _cmd_diff(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        if not target:
            self._append_result("Usa diff <target> o focus <target> primero.")
            return
        started = time.time()
        tool = self._start_tool("Diff", target, "Comparing scans…")
        init = commands.build_export_payload(target)
        diff = init.get("diff", {}) if init else {}
        self._append_bullet(f"Diff {target}")
        self._append_result(f"• Nuevos subdominios: {len(diff.get('new_subdomains', []))}")
        self._append_result(f"• Nuevos puertos: {len(diff.get('new_ports', []))}")
        self._append_result(f"• Nuevas vulnerabilidades: {len(diff.get('new_vulns', []))}")
        self._finish_tool(tool, duration=time.time() - started)

    def _cmd_export(self, args: list[str]) -> None:
        target = None
        fmt = "json"
        output = None
        idx = 0
        while idx < len(args):
            token = args[idx]
            if token in {"-f", "--format"} and idx + 1 < len(args):
                fmt = args[idx + 1]
                idx += 2
                continue
            if token in {"-o", "--output"} and idx + 1 < len(args):
                output = args[idx + 1]
                idx += 2
                continue
            if not target:
                target = token
            idx += 1
        target = commands.resolve_target(target)
        started = time.time()
        tool = self._start_tool("Export", target or "latest", "Generating summary…")
        path = commands.export_summary(target, fmt=fmt, output=output)
        if path:
            self._append_result(f"• Export: {path}")
            self._finish_tool(tool, duration=time.time() - started)
        else:
            self._finish_tool(tool, error="no export", duration=time.time() - started)

    def _cmd_doctor(self, args: list[str]) -> None:
        started = time.time()
        tool = self._start_tool("Doctor", "environment", "Checking runtime…")
        self._append_bullet("Diagnóstico del entorno")
        ok_api = commands.api_alive()
        self._append_result(f"• API: {'OK' if ok_api else 'DOWN'}")
        self._append_result(
            f"• DB: {'OK' if (commands.ROOT_DIR / 'runtime' / 'db' / 'ozyrecon.db').exists() else 'MISSING'}"
        )
        self._append_result(
            f"• Runtime: {'OK' if (commands.ROOT_DIR / 'runtime' / 'scans').exists() else 'MISSING'}"
        )
        self._append_result(f"• Python: {'OK' if Path(sys.executable).exists() else 'MISSING'}")
        self._append_result(f"• Focused target: {commands.get_focused_target() or 'n/a'}")
        self._finish_tool(tool, duration=time.time() - started)

    def _cmd_abort(self, args: list[str]) -> None:
        aborted = False
        if self._active_proc and self._active_proc.poll() is None:
            self._active_proc.terminate()
            aborted = True
            self._append_result("Scan abortado.")
        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_stop.set()
            aborted = True
            self._append_result("Watch detenido.")
        if not aborted:
            self._append_result("No hay un scan o watch activo.")

    def _cmd_scan(self, args: list[str]) -> None:
        try:
            target, opts = commands.parse_scan_tokens(args)
        except SystemExit:
            self._append_result("Uso: scan <target> [opts]")
            return
        if self._active_proc and self._active_proc.poll() is None:
            self._append_result("Ya hay un scan corriendo. Usa abort si quieres cancelarlo.")
            return

        normalized = commands.normalize_target(target)
        self._append_bullet(f"Voy a lanzar un scan real contra {normalized}.")
        tool = self._start_tool("Scan", normalized, "Launching backend…")
        start = time.time()

        def _worker() -> None:
            try:
                proc = commands.launch_scan(target, opts, background=True)
                self._active_proc = proc
                if proc.stdout is not None:
                    for line in proc.stdout:
                        line = line.rstrip()
                        if line:
                            self._push(ConversationItem(kind="system", text=line))
                rc = proc.wait()
                payload = commands.get_latest_status(target)
                counts = payload.get("counts", {})
                duration = time.time() - start
                if rc == 0:
                    self._append_result(
                        f"• Pipeline terminado: {commands.normalize_status_label(payload.get('status'))} · {counts.get('vulns', 0)} vulns"
                    )
                    self._finish_tool(tool, findings=counts.get("vulns", 0), duration=duration)
                else:
                    self._finish_tool(tool, duration=duration, error=f"exit {rc}")
                    self._append_result(f"• El proceso terminó con código {rc}.")
            except Exception as exc:
                self._finish_tool(tool, duration=time.time() - start, error=str(exc))
                self._append_result(f"• Error lanzando scan: {exc}")
            finally:
                self._active_proc = None

        threading.Thread(target=_worker, daemon=True).start()

    def run(self) -> None:
        self._append_bullet("Bienvenido. Escribe help para ver los comandos.")
        if self.recent:
            latest = self.recent[-1]
            self._append_result(
                f"Último run: {latest.get('target', 'n/a')} · {commands.normalize_status_label(latest.get('status'))}"
            )
        try:
            self._app.run()
        finally:
            self._shutdown()


def run_tui(username: str, api_base: str, api_ok: bool, recent: list[dict] | None = None) -> None:
    ClaudeLikeTUI(username=username, api_base=api_base, api_ok=api_ok, recent=recent).run()
