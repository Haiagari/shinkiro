"""
cli/tui.py  — Visual rewrite completo
Arquitectura: Window + FormattedTextControl (no TextArea) para colores reales.
Render: sin cajas, sin Frame(), sin _block(). Solo separadores, bullets y árbol.
Comandos: intactos, no se tocó ningún _cmd_*.
"""
from __future__ import annotations

import os
import shlex
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from prompt_toolkit.application import Application
from prompt_toolkit.application.current import get_app_or_none
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.filters import Condition
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    BufferControl,
    Dimension,
    FormattedTextControl,
    HSplit,
    Layout,
    ScrollablePane,
    Window,
)
from prompt_toolkit.styles import Style

from . import commands

# ── Spinner ────────────────────────────────────────────────────────────────────
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


# ── Modelo de datos ────────────────────────────────────────────────────────────
@dataclass
class ConversationItem:
    kind: str                                        # user|bullet|tool|code|result|system
    text: str = ""
    title: str = ""
    desc: str = ""
    state: str = "done"                              # running|done|error
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


# ── Utilidades de render ───────────────────────────────────────────────────────
def _cols() -> int:
    try:
        return max(60, os.get_terminal_size().columns)
    except OSError:
        return 100


def _sep() -> list[tuple[str, str]]:
    """Línea horizontal separadora — aparece solo entre mensajes de usuario."""
    return [("class:sep", "─" * _cols() + "\n")]


def _render_item(item: ConversationItem, spinner_frame: str) -> list[tuple[str, str]]:
    """
    Convierte un ConversationItem en fragmentos FormattedText.
    SIN cajas, SIN Frame(), SIN bordes completos.
    """
    frags: list[tuple[str, str]] = []

    # ── USER ──────────────────────────────────────────────────────────────────
    if item.kind == "user":
        frags += _sep()
        frags += [
            ("class:user-arrow", " ❯ "),
            ("class:user-text",  item.text + "\n"),
        ]
        frags += _sep()
        frags += [("", "\n")]

    # ── BULLET (respuesta de texto simple) ────────────────────────────────────
    elif item.kind == "bullet":
        frags += [
            ("class:bullet", " • "),
            ("class:resp",   item.text + "\n"),
            ("", "\n"),
        ]

    # ── TOOL USE ──────────────────────────────────────────────────────────────
    elif item.kind == "tool":
        name = item.title or "Tool"
        desc = item.desc or ""
        # Línea principal: • Gate(descripción)
        frags += [
            ("class:bullet",     " • "),
            ("class:tool-name",  name),
            ("class:tool-paren", "("),
            ("class:tool-desc",  desc),
            ("class:tool-paren", ")\n"),
        ]
        # Sub-línea jerárquica según estado
        if item.state == "running":
            status = item.metrics.get("status_text", "Scanning…")
            frags += [
                ("class:branch",       "    └ "),
                ("class:tool-spin",    spinner_frame + " "),
                ("class:tool-running", status + "  "),
                ("class:hint",         "(esc to interrupt)\n"),
            ]
        elif item.state == "error":
            err = item.metrics.get("error", "unknown")
            frags += [
                ("class:branch",    "    └ "),
                ("class:tool-err",  f"✗ Error: {err}\n"),
            ]
        else:
            dur      = item.metrics.get("duration", 0.0)
            findings = item.metrics.get("findings")
            if findings is not None:
                meta = f"({findings} findings · {dur:.1f}s)"
            else:
                meta = f"({dur:.1f}s)"
            frags += [
                ("class:branch",    "    └ "),
                ("class:done",      "Done  "),
                ("class:meta",      meta + "\n"),
            ]
        frags += [("", "\n")]

    # ── CODE ──────────────────────────────────────────────────────────────────
    elif item.kind == "code":
        file_label = item.metrics.get("file", "")
        hl_line    = item.metrics.get("highlight")
        start_line = item.metrics.get("start_line", 1)
        W = _cols()
        if file_label:
            bar = "─" * max(0, W - len(file_label) - 6)
            frags += [("class:code-border", f"  ┌─ {file_label} {bar}\n")]
        else:
            frags += [("class:code-border", "  ┌" + "─" * (W - 3) + "\n")]
        for i, line in enumerate(item.text.splitlines(), start=start_line):
            if i == hl_line:
                frags += [
                    ("class:hl-arrow", "▶ "),
                    ("class:lineno",   f"{i:>3} │  "),
                    ("class:code-hl",  line + "\n"),
                ]
            else:
                frags += [
                    ("",               "  "),
                    ("class:lineno",   f"{i:>3} │  "),
                    ("class:code-dim", line + "\n"),
                ]
        frags += [("class:code-border", "  └" + "─" * (W - 3) + "\n"), ("", "\n")]

    # ── RESULT (texto plano, sin decoración) ──────────────────────────────────
    elif item.kind == "result":
        for line in item.text.splitlines():
            frags += [("class:resp", "  " + line + "\n")]
        frags += [("", "\n")]

    # ── SYSTEM (output de procesos, dim) ──────────────────────────────────────
    elif item.kind == "system":
        frags += [("class:system", "  " + item.text + "\n")]

    else:
        frags += [("class:resp", item.text + "\n"), ("", "\n")]

    return frags


def _render_header(username: str, api_base: str, api_ok: bool) -> list[tuple[str, str]]:
    """Header fijo — mascota Ozy + datos de sesión, sin cajas."""
    focused = commands.get_focused_target() or "n/a"
    cwd     = str(Path.cwd())
    api_style = "class:api-ok" if api_ok else "class:api-fail"
    return [
        ("class:ozy",         " ,___,  "),
        ("class:header-title","OWL ZERO-TRUST v1.0\n"),
        ("class:ozy",         " ["),
        ("class:ozy-eye",     "O"),
        ("class:ozy",         "."),
        ("class:ozy-eye",     "O"),
        ("class:ozy",         "]  "),
        ("class:header-sub",  '"Nunca confíes, siempre verifica."\n'),
        ("class:ozy",         " /)__)  "),
        ("class:header-key",  "user: "),
        ("class:header-val",  username + "\n"),
        ("class:ozy",         ' -"--"-  '),
        ("class:header-key",  "api:  "),
        (api_style,           api_base + "\n"),
        ("class:header-pad",  "         "),
        ("class:header-key",  "focus: "),
        ("class:header-acc",  focused + "\n"),
        ("class:header-pad",  "         "),
        ("class:header-key",  "cwd:   "),
        ("class:header-dim",  cwd + "\n"),
    ]


# ── Estilos ────────────────────────────────────────────────────────────────────
OWL_STYLE = Style.from_dict({
    "":                "bg:#0d0d0f #cccccc",

    # Header
    "header":          "bg:#0d0d0f",
    "ozy":             "#E5711D",
    "ozy-eye":         "#4EC9B0",
    "header-title":    "#E5711D bold",
    "header-sub":      "#555555",
    "header-key":      "#444444",
    "header-val":      "#999999",
    "header-acc":      "#E5711D",
    "header-dim":      "#333333",
    "header-pad":      "",
    "api-ok":          "#4EC9B0",
    "api-fail":        "#F44747",

    # Separador entre mensajes de usuario
    "sep":             "#1e1e26",

    # Conversación
    "user-arrow":      "#E5711D bold",
    "user-text":       "#ffffff bold",
    "bullet":          "#E5711D",
    "resp":            "#cccccc",

    # Tool use
    "tool-name":       "#E5711D bold",
    "tool-paren":      "#555555",
    "tool-desc":       "#888888",
    "branch":          "#333333",
    "tool-spin":       "#DCDCAA",
    "tool-running":    "#DCDCAA",
    "hint":            "#444444",
    "done":            "#4EC9B0 bold",
    "meta":            "#555555",
    "tool-err":        "#F44747",

    # Código
    "code-border":     "#333333",
    "lineno":          "#3a3a3a",
    "code-dim":        "#777777",
    "code-hl":         "bg:#2a0e0e #F44747",
    "hl-arrow":        "#F44747 bold",

    # System output
    "system":          "#555555",

    # Prompt
    "prompt-bar":      "bg:#0d0d10",
    "prompt-arrow":    "#E5711D bold",
    "prompt-border":   "#1e1e26",
})


# ── TUI principal ──────────────────────────────────────────────────────────────
class ClaudeLikeTUI:
    def __init__(
        self,
        username: str,
        api_base: str,
        api_ok: bool,
        recent: list[dict] | None = None,
    ) -> None:
        self.username = username
        self.api_base = api_base
        self.api_ok   = api_ok
        self.recent   = recent or []

        self.items:   list[ConversationItem] = []
        self._lock    = threading.RLock()

        self._active_proc   = None
        self._active_task:  ConversationItem | None = None
        self._spinner_running = False
        self._spinner_thread: threading.Thread | None = None
        self._spinner_frame = SPINNER_FRAMES[0]
        self._watch_stop    = threading.Event()
        self._app:          Application | None = None

        # Scroll manual
        self._scroll_offset = 0       # líneas desde el fondo (0 = al fondo)
        self.follow_tail    = True

        self._build_ui()

    # ── Construcción del layout ────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Header (Window + FormattedTextControl para colores) ──
        self._header_ctrl = FormattedTextControl(
            text=lambda: FormattedText(
                _render_header(self.username, self.api_base, self.api_ok)
            )
        )
        header_win = Window(
            content=self._header_ctrl,
            height=5,
            style="class:header",
            dont_extend_height=True,
        )

        # ── Línea divisora entre header y conversación ──
        divider = Window(
            content=FormattedTextControl(
                lambda: FormattedText([("class:sep", "─" * _cols())])
            ),
            height=1,
            dont_extend_height=True,
        )

        # ── Área de conversación (scroll manual) ──
        self._conv_ctrl = FormattedTextControl(
            text=self._render_conversation,
            focusable=False,
        )
        conv_win = Window(
            content=self._conv_ctrl,
            style="",
            dont_extend_height=False,
            wrap_lines=True,
        )

        # ── Prompt inferior ──
        self.input_buffer = Buffer(
            name="main_input",
            accept_handler=self._on_submit,
            multiline=False,
        )
        prompt_border = Window(
            content=FormattedTextControl(
                lambda: FormattedText([("class:prompt-border", "─" * _cols())])
            ),
            height=1,
            dont_extend_height=True,
        )
        prompt_prefix = Window(
            content=FormattedTextControl(
                lambda: FormattedText([("class:prompt-arrow", " ❯ ")])
            ),
            width=3,
            dont_extend_width=True,
            dont_extend_height=True,
        )
        prompt_input = Window(
            content=BufferControl(
                buffer=self.input_buffer,
                focusable=True,
                focus_on_click=True,
            ),
            height=1,
            dont_extend_height=True,
            style="class:prompt-bar",
        )
        from prompt_toolkit.layout.containers import VSplit
        prompt_row = VSplit([prompt_prefix, prompt_input])
        prompt_area = HSplit([prompt_border, prompt_row])

        # ── Layout raíz ──
        root = HSplit([
            header_win,
            divider,
            conv_win,
            prompt_area,
        ])

        # ── Key bindings ──
        kb = KeyBindings()

        @kb.add("c-c")
        def _(event):
            if self._active_proc and self._active_proc.poll() is None:
                self.abort_active(); return
            event.app.exit()

        @kb.add("c-d")
        def _(event):
            event.app.exit()

        @kb.add("escape")
        def _(event):
            if self._active_proc and self._active_proc.poll() is None:
                self.abort_active(); return
            self.follow_tail = True
            self._scroll_offset = 0
            self._invalidate()

        @kb.add("pageup")
        def _(event):
            self.follow_tail = False
            self._scroll_offset += 8
            self._invalidate()

        @kb.add("pagedown")
        def _(event):
            self._scroll_offset = max(0, self._scroll_offset - 8)
            if self._scroll_offset == 0:
                self.follow_tail = True
            self._invalidate()

        @kb.add("home")
        def _(event):
            self.follow_tail = False
            self._scroll_offset = 999_999
            self._invalidate()

        @kb.add("end")
        def _(event):
            self.follow_tail = True
            self._scroll_offset = 0
            self._invalidate()

        self._app = Application(
            layout=Layout(root, focused_element=self.input_buffer),
            key_bindings=kb,
            style=OWL_STYLE,
            full_screen=True,
            mouse_support=True,
        )

        # Forzar foco al prompt al arrancar
        self._app.pre_run_callables.append(
            lambda: self._app.layout.focus(self.input_buffer)
        )

    # ── Render de conversación ─────────────────────────────────────────────────

    def _render_conversation(self) -> FormattedText:
        with self._lock:
            items = list(self.items)

        if not items:
            return FormattedText([
                ("class:hint", "\n  Escribe "),
                ("class:bullet", "help"),
                ("class:hint", " para ver los comandos disponibles.\n"),
            ])

        # Construir todos los fragmentos
        all_frags: list[tuple[str, str]] = []
        for item in items:
            all_frags.extend(_render_item(item, self._spinner_frame))

        if not self.follow_tail and self._scroll_offset > 0:
            # Scroll manual: contar líneas y recortar desde arriba
            lines: list[list[tuple[str, str]]] = [[]]
            for frag in all_frags:
                style, text = frag
                parts = text.split("\n")
                lines[-1].append((style, parts[0]))
                for part in parts[1:]:
                    lines.append([(style, part)])

            total = len(lines)
            # Calcular altura visible aproximada
            try:
                term_h = os.get_terminal_size().lines
            except OSError:
                term_h = 30
            visible = max(10, term_h - 8)
            offset  = min(self._scroll_offset, max(0, total - visible))
            start   = max(0, total - visible - offset)
            visible_lines = lines[start: start + visible]

            result: list[tuple[str, str]] = []
            for i, line_frags in enumerate(visible_lines):
                for f in line_frags:
                    result.append(f)
                if i < len(visible_lines) - 1:
                    result.append(("", "\n"))
            return FormattedText(result)

        return FormattedText(all_frags)

    # ── Invalidate ─────────────────────────────────────────────────────────────

    def _invalidate(self) -> None:
        app = self._app or get_app_or_none()
        if app is not None:
            app.invalidate()

    # ── Spinner ────────────────────────────────────────────────────────────────

    def _ensure_spinner(self) -> None:
        if self._spinner_running:
            return
        self._spinner_running = True

        def _loop():
            i = 0
            while self._spinner_running:
                self._spinner_frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
                self._invalidate()
                time.sleep(0.08)
                i += 1

        self._spinner_thread = threading.Thread(target=_loop, daemon=True)
        self._spinner_thread.start()

    def _stop_spinner(self) -> None:
        self._spinner_running = False

    # ── Mutaciones de conversación ─────────────────────────────────────────────

    def _push(self, item: ConversationItem) -> ConversationItem:
        with self._lock:
            self.items.append(item)
        if self.follow_tail:
            self._scroll_offset = 0
        self._invalidate()
        return item

    def _append_user(self, text: str) -> None:
        self._push(ConversationItem(kind="user", text=text))

    def _append_bullet(self, text: str) -> None:
        self._push(ConversationItem(kind="bullet", text=text))

    def _append_result(self, text: str) -> None:
        self._push(ConversationItem(kind="result", text=text))

    def _append_code(self, text: str) -> None:
        self._push(ConversationItem(kind="code", text=text))

    def _start_tool(self, title: str, desc: str, status_text: str = "Scanning…") -> ConversationItem:
        tool = self._push(ConversationItem(
            kind="tool", title=title, desc=desc, state="running",
            metrics={"status_text": status_text},
        ))
        self._active_task = tool
        self._ensure_spinner()
        return tool

    def _finish_tool(
        self,
        tool: ConversationItem,
        *,
        findings: int | None = None,
        duration: float = 0.0,
        error: str | None = None,
    ) -> None:
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

    def _update_active_tool(self, **metrics: Any) -> None:
        with self._lock:
            if not self._active_task:
                return
            self._active_task.metrics.update(metrics)
        self._invalidate()

    # ── Submit ─────────────────────────────────────────────────────────────────

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
            return
        if not tokens:
            return
        cmd, args = tokens[0].lower(), tokens[1:]
        handlers: dict[str, Callable[[list[str]], None]] = {
            "scan":     self._cmd_scan,
            "status":   self._cmd_status,
            "history":  self._cmd_history,
            "report":   self._cmd_report,
            "overview": self._cmd_overview,
            "targets":  self._cmd_targets,
            "inspect":  self._cmd_inspect,
            "watch":    self._cmd_watch,
            "focus":    self._cmd_focus,
            "diff":     self._cmd_diff,
            "export":   self._cmd_export,
            "doctor":   self._cmd_doctor,
            "abort":    self._cmd_abort,
            "help":     self._cmd_help,
            "exit":     self._cmd_exit,
            "quit":     self._cmd_exit,
        }
        handler = handlers.get(cmd)
        if not handler:
            self._append_result(f"Comando desconocido: {cmd}. Escribe help.")
            return
        handler(args)

    # ── Comandos (sin cambios respecto al original) ────────────────────────────

    def _cmd_help(self, args: list[str]) -> None:
        self._append_bullet("Comandos disponibles:")
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
            "abort                  cerrar scan activo",
            "exit|quit              salir",
        ]:
            self._append_result(f"  {line}")

    def _cmd_exit(self, args: list[str]) -> None:
        if self._app:
            self._app.exit()

    def abort_active(self) -> None:
        self._cmd_abort([])

    def _cmd_focus(self, args: list[str]) -> None:
        target = args[0] if args else None
        focused = commands.set_focused_target(target) if target else commands.get_focused_target()
        if not focused:
            self._append_result("Usa focus <target>."); return
        self._append_bullet(f"Target activo fijado en {focused}")
        current = commands.get_latest_status(focused)
        self._append_result(f"• Estado: {commands.normalize_status_label(current.get('status'))}")
        self._append_result(f"• Fase: {current.get('phase', 'none')}")
        self._append_result(f"• Progreso: {current.get('progress', 0)}%")

    def _cmd_status(self, args: list[str]) -> None:
        target  = commands.resolve_target(args[0] if args else None)
        payload = commands.get_latest_status(target)
        self._append_bullet(f"Estado de {payload.get('target', target or 'latest')}")
        self._append_result(f"• Estado: {commands.normalize_status_label(payload.get('status'))}")
        self._append_result(f"• Fase: {payload.get('phase', 'none')}")
        self._append_result(f"• Progreso: {payload.get('progress', 0)}%")
        self._append_result(f"• Mensaje: {payload.get('message') or '—'}")

    def _cmd_history(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        items  = commands.get_history(target, limit=8)
        self._append_bullet(f"Historial {target or 'global'}")
        for item in items[:8]:
            self._append_result(
                f"• #{item.get('scan_id','')} {item.get('target','n/a')} · "
                f"{commands.normalize_status_label(item.get('status'))} · "
                f"{item.get('progress',0)}%"
            )

    def _cmd_report(self, args: list[str]) -> None:
        target  = commands.resolve_target(args[0] if args else None)
        payload = commands.get_latest_status(target)
        counts  = payload.get("counts", {})
        self._append_bullet(f"Reporte de {payload.get('target', target or 'latest')}")
        self._append_result(f"• Subdominios: {counts.get('subdomains', 0)}")
        self._append_result(f"• Hosts vivos: {counts.get('live_hosts', 0)}")
        self._append_result(f"• Puertos: {counts.get('ports', 0)}")
        self._append_result(f"• Vulns: {counts.get('vulns', 0)}")

    def _cmd_overview(self, args: list[str]) -> None:
        target  = commands.resolve_target(args[0] if args else None)
        tool    = self._start_tool("Overview", target or "latest", "Reading framework state…")
        payload = commands.build_export_payload(target)
        if not payload:
            self._finish_tool(tool, error="no data")
            self._append_result("No se pudo leer el estado del framework."); return
        project    = payload.get("project", {})
        stats      = payload.get("stats", {})
        scan_status= payload.get("scan_status", {})
        findings   = payload.get("findings", [])
        self._append_bullet(f"{project.get('name','BugBounty Framework')} · {project.get('target','n/a')}")
        self._append_result(f"• Run: {project.get('run','n/a')}")
        self._append_result(f"• Estado: {commands.normalize_status_label(project.get('status'))}")
        self._append_result(
            f"• Resumen: {stats.get('subdomains',0)} subs · "
            f"{stats.get('hosts',0)} hosts · {stats.get('ports',0)} puertos"
        )
        self._append_result(f"• Hallazgos: {len(findings)}")
        self._append_result(f"• Progreso: {scan_status.get('progress',0)}%")
        self._finish_tool(tool, findings=len(findings), duration=0.0)

    def _cmd_targets(self, args: list[str]) -> None:
        tool = self._start_tool("Targets", "monitored", "Loading targets…")
        self._append_bullet("Targets monitoreados:")
        for line in commands.list_known_targets():
            self._append_result(f"• {line}")
        self._finish_tool(tool, duration=0.0)

    def _cmd_inspect(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        run    = args[1] if len(args) > 1 else None
        if not target:
            self._append_result("Usa inspect <target> [run] o focus <target> primero."); return
        tool = self._start_tool("Inspect", target, "Opening scan details…")
        resolved = run
        if not resolved:
            latest = commands._latest_scan_for_target(target)
            if latest and latest.out_dir:
                resolved = Path(latest.out_dir).name
        if not resolved:
            self._finish_tool(tool, error="no scan")
            self._append_result(f"No hay scans para {target}."); return
        payload = commands.api_json(f"/scan/{target}/{resolved}")
        if not isinstance(payload, dict):
            self._finish_tool(tool, error="offline")
            self._append_result(f"No se pudo abrir el scan {target}/{resolved}."); return
        data   = payload.get("data", {})
        status = data.get("status", {})
        self._append_bullet(f"Inspect {target} · run {resolved}")
        if status:
            self._append_result(f"• Estado: {commands.normalize_status_label(status.get('status'))}")
            self._append_result(f"• Fase: {status.get('phase','unknown')}")
            self._append_result(f"• Progreso: {status.get('progress',0)}%")
        for sec, value in data.items():
            if sec == "status": continue
            count = len(value) if isinstance(value, (list, dict)) else 1
            self._append_result(f"• {sec}: {count}")
        self._finish_tool(tool, duration=0.0)

    def _cmd_watch(self, args: list[str]) -> None:
        target   = commands.resolve_target(args[0] if args else None)
        if not target:
            self._append_result("Usa watch <target> o focus <target> primero."); return
        interval = 2.0
        count    = None
        idx      = 1 if args else 0
        while idx < len(args):
            token = args[idx]
            if token in {"-i","--interval"} and idx+1 < len(args):
                try: interval = float(args[idx+1])
                except ValueError: interval = 2.0
                idx += 2; continue
            if token in {"-n","--count"} and idx+1 < len(args):
                try: count = int(args[idx+1])
                except ValueError: count = None
                idx += 2; continue
            idx += 1
        tool = self._start_tool("Watch", target, "Watching live scan…")
        self._watch_stop.clear()

        def _worker():
            cycles = 0
            try:
                while not self._watch_stop.is_set():
                    payload = commands.get_latest_status(target)
                    with self._lock:
                        tool.metrics["status_text"] = (
                            f"{commands.normalize_status_label(payload.get('status'))} · "
                            f"{payload.get('progress',0)}%"
                        )
                    self._invalidate()
                    if commands.is_terminal_status(payload.get("status")): break
                    cycles += 1
                    if count is not None and cycles >= count: break
                    time.sleep(interval)
                payload = commands.get_latest_status(target)
                self._finish_tool(
                    tool, duration=0.0,
                    findings=payload.get("counts",{}).get("vulns",0)
                    if isinstance(payload.get("counts"),dict) else None,
                )
            except Exception as exc:
                self._finish_tool(tool, error=str(exc))
                self._append_result(f"Watch error: {exc}")

        threading.Thread(target=_worker, daemon=True).start()

    def _cmd_diff(self, args: list[str]) -> None:
        target = commands.resolve_target(args[0] if args else None)
        if not target:
            self._append_result("Usa diff <target> o focus <target> primero."); return
        tool = self._start_tool("Diff", target, "Comparing scans…")
        init = commands.build_export_payload(target)
        diff = init.get("diff", {}) if init else {}
        self._append_bullet(f"Diff {target}")
        self._append_result(f"• Nuevos subdominios: {len(diff.get('new_subdomains',[]))}")
        self._append_result(f"• Nuevos puertos: {len(diff.get('new_ports',[]))}")
        self._append_result(f"• Nuevas vulnerabilidades: {len(diff.get('new_vulns',[]))}")
        self._finish_tool(tool, duration=0.0)

    def _cmd_export(self, args: list[str]) -> None:
        target = None; fmt = "json"; output = None; idx = 0
        while idx < len(args):
            token = args[idx]
            if token in {"-f","--format"} and idx+1 < len(args):
                fmt = args[idx+1]; idx += 2; continue
            if token in {"-o","--output"} and idx+1 < len(args):
                output = args[idx+1]; idx += 2; continue
            if not target: target = token
            idx += 1
        target = commands.resolve_target(target)
        tool   = self._start_tool("Export", target or "latest", "Generating summary…")
        path   = commands.export_summary(target, fmt=fmt, output=output)
        if path:
            self._append_result(f"• Export: {path}")
            self._finish_tool(tool, duration=0.0)
        else:
            self._finish_tool(tool, error="no export")

    def _cmd_doctor(self, args: list[str]) -> None:
        tool = self._start_tool("Doctor", "environment", "Checking runtime…")
        self._append_bullet("Diagnóstico del entorno")
        ok_api = commands.api_alive()
        self._append_result(f"• API: {'OK' if ok_api else 'DOWN'}")
        self._append_result(
            f"• DB: {'OK' if (commands.ROOT_DIR/'runtime'/'db'/'bugbounty.db').exists() else 'MISSING'}"
        )
        self._append_result(
            f"• Runtime: {'OK' if (commands.ROOT_DIR/'runtime'/'scans').exists() else 'MISSING'}"
        )
        self._append_result(f"• Python: {'OK' if Path(sys.executable).exists() else 'MISSING'}")
        self._finish_tool(tool, duration=0.0)

    def _cmd_abort(self, args: list[str]) -> None:
        if self._active_proc and self._active_proc.poll() is None:
            self._active_proc.terminate()
            self._append_result("Scan abortado.")
        else:
            self._watch_stop.set()
            self._append_result("No hay un scan activo.")

    def _cmd_scan(self, args: list[str]) -> None:
        try:
            target, opts = commands.parse_scan_tokens(args)
        except SystemExit:
            self._append_result("Uso: scan <target> [opts]"); return
        if self._active_proc and self._active_proc.poll() is None:
            self._append_result("Ya hay un scan corriendo. Usa abort si quieres cancelarlo."); return
        self._append_bullet(f"Voy a lanzar un scan real contra {commands.normalize_target(target)}.")
        tool  = self._start_tool("Scan", commands.normalize_target(target), "Launching backend…")
        start = time.time()

        def _worker():
            proc = commands.launch_scan(target, opts, background=True)
            self._active_proc = proc
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        self._push(ConversationItem(kind="system", text=line))
                rc      = proc.wait()
                payload = commands.get_latest_status(target)
                counts  = payload.get("counts", {})
                dur     = time.time() - start
                if rc == 0:
                    self._append_result(
                        f"• Pipeline terminado: "
                        f"{commands.normalize_status_label(payload.get('status'))} · "
                        f"{counts.get('vulns',0)} vulns"
                    )
                    self._finish_tool(tool, findings=counts.get("vulns",0), duration=dur)
                else:
                    self._finish_tool(tool, duration=dur, error=f"exit {rc}")
                    self._append_result(f"• El proceso terminó con código {rc}.")
            finally:
                self._active_proc = None

        threading.Thread(target=_worker, daemon=True).start()

    # ── Run ────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._append_bullet("Bienvenido. Escribe help para ver los comandos.")
        self._app.run()


def run_tui(
    username: str,
    api_base: str,
    api_ok: bool,
    recent: list[dict] | None = None,
) -> None:
    ClaudeLikeTUI(
        username=username,
        api_base=api_base,
        api_ok=api_ok,
        recent=recent,
    ).run()
