from __future__ import annotations

import curses
import os
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

from .assistant import OPERATIONS, AssistantStep, Operation, field_def, operation_flow, operation_meta, visible_fields
from .focus import FocusState
from .glyphs import ASCII_GLYPHS, Glyphs, UNICODE_GLYPHS, braille_texture, current_glyphs, step_glyph
from .logstore import LogStore
from .modals import ConfirmModal
from .models import DIAG_STAGE_DEFS, INSTALL_STAGE_DEFS, UNINSTALL_STAGE_DEFS, DiagnoseSpec, InstallSpec, OperationResult, RunnerError, RunState, UninstallSpec
from .rendering import BufferSurface, CursesSurface, choose_layout, ellipsis_clip, key_value_row, progress_bar, section_heading, soft_panel, titled_rule, wrap_paragraph
from .runner import OperationRunner
from .screens import FIELD_INDEX_INSTALL, FIELD_INDEX_UNINSTALL, INSTALL_FIELDS, UNINSTALL_FIELDS, FieldDef, build_review_rows
from .state import UIState, apply_runner_event, new_run_state
from .system_ops import AppPaths, CancelToken, detect_arch, detect_host, detect_letsencrypt_cert_pair, detect_paths, detect_proxy_candidates, detect_service_state
from .theme import Theme
from .views import clamp
from .widgets import Rect


@dataclass
class WizardState:
    operation: Operation = "install"
    step_idx: int = 0
    field_idx: int = 0


_PROGRESS_STAGE_INDEX = {
    "install": 4,
    "uninstall": 3,
    "diagnose": 1,
}

_COMPLETION_STAGE_INDEX = {
    "install": 5,
    "uninstall": 4,
    "diagnose": 2,
}


STAGE_META: dict[str, tuple[str, str]] = {
    "preflight": ("Preflight", "info"),
    "fetch_source": ("Fetch", "info"),
    "deps": ("Dependencies", "warning"),
    "build": ("Build", "primary"),
    "filesystem_and_user": ("Filesystem", "info"),
    "env_generation": ("Environment", "info"),
    "service_install_start": ("Service", "primary"),
    "firewall": ("Firewall", "warning"),
    "proxy": ("Proxy", "warning"),
    "post_checks": ("Checks", "primary"),
    "final_summary": ("Summary", "info"),
    "backups": ("Backups", "info"),
    "cleanup": ("Cleanup", "warning"),
    "service": ("Service", "warning"),
    "summary": ("Summary", "info"),
    "diagnostics": ("Diagnostics", "primary"),
}


def _autofill_proxy_tls_paths(spec: InstallSpec) -> bool:
    if not spec.proxy_setup or not spec.proxy_tls:
        return False
    server_name = (spec.proxy_server_name or spec.base_domain or "").strip()
    if not server_name:
        return False
    if spec.proxy_cert and spec.proxy_key:
        return False
    cert, key = detect_letsencrypt_cert_pair(server_name)
    changed = False
    if cert and not spec.proxy_cert:
        spec.proxy_cert = cert
        changed = True
    if key and not spec.proxy_key:
        spec.proxy_key = key
        changed = True
    return changed


def _seed_proxy_tls_defaults(spec: InstallSpec) -> bool:
    server_name = (spec.proxy_server_name or spec.base_domain or "").strip()
    if not server_name:
        return False
    cert, key = detect_letsencrypt_cert_pair(server_name)
    if not cert or not key:
        return False
    changed = False
    if not spec.proxy_cert:
        spec.proxy_cert = cert
        changed = True
    if not spec.proxy_key:
        spec.proxy_key = key
        changed = True
    if spec.proxy_setup and not spec.proxy_tls:
        spec.proxy_tls = True
        changed = True
    return changed


class DespatchTUI:
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr = stdscr
        self.theme = Theme(has_color=False)
        self.glyphs = current_glyphs()
        self.ui = UIState(mode="welcome")
        self.focus = FocusState()
        self.mouse_targets: list[Rect] = []

        self.paths: AppPaths = detect_paths()
        self.runner = OperationRunner(self.paths)
        self.logstore = LogStore(max_entries=8000)
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.run_thread: threading.Thread | None = None
        self.cancel_token: CancelToken | None = None
        self.run_state: RunState | None = None
        self.last_result: OperationResult | None = None
        self.last_summary_payload: dict[str, Any] = {}
        self.active_operation: str = ""

        hostname = detect_host()
        default_domain = hostname if "." in hostname else "example.com"
        proxies = detect_proxy_candidates()
        self.install_spec = InstallSpec(
            base_domain=default_domain,
            proxy_server=proxies[0] if proxies else "nginx",
            proxy_server_name=default_domain,
        )
        _seed_proxy_tls_defaults(self.install_spec)
        _autofill_proxy_tls_paths(self.install_spec)
        self.uninstall_spec = UninstallSpec()

        self.selected_operation = 0
        self.wizard = WizardState(operation="install", step_idx=0, field_idx=0)
        self.log_category_mask: set[str] = {"system", "network", "proxy", "service", "auth"}
        self.log_level_order = ["debug", "info", "warn", "error"]
        self.ui.status_line = f"Ready. Log file: {self.logstore.log_path}"
        self.running = True

    def run(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(False)
        self.stdscr.timeout(120)
        self.stdscr.keypad(True)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        os.environ.setdefault("ESCDELAY", "25")
        self.theme = Theme.init()
        self.glyphs = current_glyphs()

        while self.running:
            self._drain_events()
            self._draw()
            self.ui.spinner_tick += 1
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                key = None
            if key is None:
                continue
            self._handle_key(key)

    def _draw(self) -> None:
        self.stdscr.erase()
        self.mouse_targets = []
        h, w = self.stdscr.getmaxyx()
        if h < 24 or w < 96:
            surface = CursesSurface(self.stdscr, self.theme)
            surface.text(0, 0, "Terminal too small. Resize to at least 96x24.", "error")
            self.stdscr.refresh()
            return
        surface = CursesSurface(self.stdscr, self.theme)
        self._draw_shell(surface)
        self.stdscr.refresh()

    def _draw_shell(self, surface: CursesSurface) -> None:
        h, w = surface.height, surface.width
        tier = choose_layout(w, h)
        outer_y = 1
        outer_x = 2
        outer_h = h - 2
        outer_w = w - 4
        surface.box(outer_y, outer_x, outer_h, outer_w, self.glyphs, "chrome")

        inner_x = outer_x + 1
        inner_y = outer_y + 1
        inner_w = outer_w - 2
        inner_h = outer_h - 2

        title_h = tier.title_h
        footer_h = tier.footer_h
        footer_y = outer_y + outer_h - footer_h
        header_divider_y = inner_y + title_h - 1
        footer_divider_y = footer_y - 1
        rail_w = tier.rail_w
        rail_x = inner_x
        rail_y = header_divider_y + 1
        rail_h = max(0, footer_divider_y - rail_y)
        main_x = rail_x + rail_w + 2
        main_y = rail_y
        main_w = inner_w - rail_w - 3
        main_h = rail_h

        surface.hline(header_divider_y, inner_x, inner_w, self.glyphs.box_h, "chrome")
        surface.hline(footer_divider_y, inner_x, inner_w, self.glyphs.box_h, "chrome")
        surface.vline(rail_y, rail_x + rail_w, rail_h, self.glyphs.box_v, "rail")

        self._draw_titlebar(surface, inner_x, inner_y, inner_w, title_h)
        self._draw_rail(surface, rail_x, rail_y, rail_w, rail_h)
        self._draw_main(surface, main_x, main_y, main_w, main_h, tier)
        self._draw_footer(surface, inner_x, footer_y, inner_w, footer_h)

    def _draw_titlebar(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        title = "Despatch Installer Assistant"
        sub = f"{detect_host()}  ·  service:{detect_service_state()}  ·  arch:{detect_arch()}"
        center_x = x + max(0, (w - len(title)) // 2)
        surface.text(y, center_x, title, "titlebar")
        mode_label = "UTF-8" if self.glyphs.unicode else "ASCII"
        meta_w = max(12, w - len(mode_label) - 8)
        surface.text(y + 1, x + 2, ellipsis_clip(sub, meta_w, self.glyphs), "rail")
        surface.text(y + 1, x + max(2, w - len(mode_label) - 2), mode_label, "rail")
        if self.ui.mode == "welcome":
            hint = "Installer flow is guided. Only one decision is emphasized at a time."
        else:
            meta = operation_meta(self.wizard.operation)
            hint = f"{meta.short_title}  ·  {self._current_step().title}"
        surface.text(y + 2, x + 2, ellipsis_clip(hint, max(8, w - 4), self.glyphs), "muted")

    def _label_width(self, width: int) -> int:
        return 24 if width >= 78 else 20

    def _draw_rail(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        ill_h = 7 if h >= 18 else 5
        surface.text(y, x + 2, "DESPATCH", "heading")
        texture = braille_texture(max(8, w - 4), ill_h - 1, self.glyphs)
        for idx, line in enumerate(texture[: max(0, ill_h - 1)]):
            surface.text(y + 1 + idx, x + 2, ellipsis_clip(line, max(8, w - 4), self.glyphs), "rail")

        rail_y = y + ill_h + 1
        if self.ui.mode == "welcome":
            intro = [
                "Guided linear flow",
                "Quiet hierarchy",
                "Safe fallbacks for root-required work",
            ]
            for idx, item in enumerate(intro):
                surface.text(rail_y + idx * 2, x + 2, ellipsis_clip(f"{self.glyphs.bullet} {item}", max(8, w - 4), self.glyphs), "panel")
            return

        flow = operation_flow(self.wizard.operation)
        meta = operation_meta(self.wizard.operation)
        surface.text(rail_y, x + 2, meta.accent, "heading")
        step_y = rail_y + 2
        current_idx = self.wizard.step_idx
        show_timeline = bool(self.run_state and self.ui.mode == "assistant" and self._current_step().kind in {"progress", "completion"})
        step_gap = 1 if show_timeline else 2
        for idx, step in enumerate(flow):
            line_y = step_y + idx * step_gap
            if line_y >= y + h - 2:
                break
            status = "pending"
            active = idx == current_idx
            if idx < current_idx:
                status = "ok"
            glyph = step_glyph(status, active=active, glyphs=self.glyphs)
            style = "heading" if active else "panel"
            if idx < current_idx:
                style = "success"
            surface.fill(line_y, x + 2, 1, max(0, w - 4), " ", "panel")
            surface.text(line_y, x + 2, ellipsis_clip(f"{glyph} {step.title}", max(8, w - 4), self.glyphs), style)

        if show_timeline:
            base = min(y + h - 9, step_y + len(flow) * step_gap + 1)
            surface.fill(base, x + 2, 1, max(0, w - 4), " ", "panel")
            titled_rule(surface, base, x + 2, max(8, w - 4), "Stage timeline", self.glyphs, title_style="heading")
            stage_row = base + 2
            for stage_id in self.run_state.stage_order[: max(0, y + h - stage_row - 1)]:
                stage = self.run_state.stages[stage_id]
                label, _ = STAGE_META.get(stage_id, (stage.title, "info"))
                glyph = step_glyph(stage.status, active=stage.stage_id == self.run_state.active_stage_id, glyphs=self.glyphs)
                style = "panel"
                if stage.status == "ok":
                    style = "success"
                elif stage.status == "failed":
                    style = "error"
                elif stage.status == "running":
                    style = "primary"
                elif stage.status == "pending":
                    style = "muted"
                surface.fill(stage_row, x + 2, 1, max(0, w - 4), " ", "panel")
                surface.text(stage_row, x + 2, ellipsis_clip(f"{glyph} {label}", max(8, w - 4), self.glyphs), style)
                stage_row += 1
                if stage_row >= y + h - 1:
                    break

    def _draw_main(self, surface: CursesSurface, x: int, y: int, w: int, h: int, tier: Any) -> None:
        if self.ui.mode == "welcome":
            self._draw_welcome(surface, x, y, w, h)
            return
        step = self._current_step()
        if step.kind == "form":
            self._draw_form_step(surface, step, x, y, w, h)
            return
        if step.kind == "review":
            self._draw_review_step(surface, x, y, w, h)
            return
        if step.kind == "status":
            self._draw_status_step(surface, x, y, w, h)
            return
        if step.kind == "intro":
            self._draw_intro_step(surface, x, y, w, h)
            return
        if step.kind == "progress":
            self._draw_progress_step(surface, x, y, w, h, tier)
            return
        self._draw_completion_step(surface, x, y, w, h, tier)

    def _draw_welcome(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        copy = (
            "This assistant prepares installation, removal, diagnostics, and host inspection using a guided flow. "
            "Review the selected task, then continue to the next screen."
        )
        card_y = section_heading(surface, y + 1, x + 1, w - 2, "Welcome to the Despatch Installer", copy, glyphs=self.glyphs)
        compact = h < 18
        card_h = 1 if compact else 4
        gap = 0 if compact else 1
        items: list[str] = []
        for idx, meta in enumerate(OPERATIONS):
            top = card_y + idx * (card_h + gap)
            if top + card_h >= y + h - 2:
                break
            selected = idx == self.selected_operation
            fid = f"welcome:card:{idx}"
            items.append(fid)
            self._draw_card(surface, top, x + 1, w - 2, card_h, meta.title, meta.summary, meta.risk, selected, self.focus.current == fid)
            self.mouse_targets.append(Rect(top, x + 1, max(1, card_h), w - 2, fid))

        items.extend(["welcome:action:quit", "welcome:action:continue"])
        preferred = self.focus.current if self.focus.current in items else f"welcome:card:{self.selected_operation}"
        self.focus.set_items(items, preferred=preferred)

    def _draw_card(self, surface: CursesSurface, y: int, x: int, w: int, h: int, title: str, summary: str, risk: str, selected: bool, focused: bool) -> None:
        if h <= 1:
            style = "focus" if focused else ("heading" if selected else "panel")
            marker = self.glyphs.card_on if selected else self.glyphs.card_off
            available = max(8, w - len(risk) - 5)
            surface.text(y, x + 1, ellipsis_clip(f"{marker} {title}", available, self.glyphs), style)
            risk_style = "warning" if risk == "HIGH" else "rail"
            surface.text(y, x + max(2, w - len(risk) - 1), risk, risk_style)
            return
        surface.box(y, x, h, w, self.glyphs, "selection" if selected else "chrome")
        marker = self.glyphs.card_on if selected else self.glyphs.card_off
        if selected:
            surface.text(y + 1, x + 1, self.glyphs.marker, "primary")
        title_style = "focus" if focused else ("heading" if selected else "panel")
        surface.text(y + 1, x + 2, ellipsis_clip(f"{marker} {title}", max(8, w - len(risk) - 8), self.glyphs), title_style)
        risk_style = "warning" if risk == "HIGH" else "rail"
        surface.text(y + 1, x + max(2, w - len(risk) - 4), risk, risk_style)
        if h >= 4:
            surface.text(y + 2, x + 2, ellipsis_clip(summary, max(8, w - 4), self.glyphs), "muted")

    def _draw_form_step(self, surface: CursesSurface, step: AssistantStep, x: int, y: int, w: int, h: int) -> None:
        values = self._current_values()
        names = visible_fields(self.wizard.operation, step, values)
        items: list[str] = []
        row = section_heading(surface, y + 1, x + 1, w - 2, step.title, step.summary, glyphs=self.glyphs)

        if self.wizard.operation == "install" and step.key == "scope":
            row = self._draw_info_block(
                surface,
                row,
                x + 1,
                w - 2,
                [
                    f"Host: {detect_host()}",
                    f"Service state: {detect_service_state()}",
                    f"Root dir: {self.paths.root_dir}",
                    f"Scripts dir: {self.paths.scripts_dir}",
                ],
                title="Host summary",
            )
        elif self.wizard.operation == "install" and step.key == "network":
            hints = [
                f"Detected proxies: {', '.join(detect_proxy_candidates()) or 'none'}",
                f"Suggested base domain: {self.install_spec.base_domain}",
            ]
            row = self._draw_info_block(surface, row, x + 1, w - 2, hints, title="Detected")
        elif self.wizard.operation == "install" and step.key == "security":
            hints = [
                "PAM mode is recommended for local system auth.",
                "SQL mode requires both driver and DSN before install can start.",
                "Proxy TLS auto-fills detected Let's Encrypt paths when possible.",
            ]
            row = self._draw_info_block(surface, row, x + 1, w - 2, hints, title="Notes")
        elif self.wizard.operation == "uninstall" and step.key == "backup":
            hints = [
                "Backups are exported before destructive cleanup when enabled.",
                "Use review to confirm the exact removal scope.",
            ]
            row = self._draw_info_block(surface, row, x + 1, w - 2, hints, title="Backup notes")

        self.wizard.field_idx = clamp(self.wizard.field_idx, 0, max(0, len(names) - 1))
        for idx, name in enumerate(names):
            field = field_def(self.wizard.operation, name)
            if field is None:
                continue
            fid = f"field:{name}"
            items.append(fid)
            focused = self.focus.current == fid or (not self.focus.current and idx == self.wizard.field_idx)
            start_row = row
            row = self._draw_field_row(surface, row, x + 1, w - 2, field, getattr(values, name), focused)
            self.mouse_targets.append(Rect(start_row, x + 1, max(1, row - start_row), w - 2, fid))
            if row >= y + h - 4:
                break

        items.extend(self._footer_action_ids())
        preferred = self.focus.current if self.focus.current in items else (f"field:{names[self.wizard.field_idx]}" if names else self._footer_action_ids()[-1])
        self.focus.set_items(items, preferred=preferred)

    def _draw_info_block(self, surface: CursesSurface, y: int, x: int, w: int, lines: list[str], title: str = "") -> int:
        row = soft_panel(surface, y, x, w, lines, glyphs=self.glyphs, title=title)
        return row + 1

    def _draw_field_row(self, surface: CursesSurface, y: int, x: int, w: int, field: FieldDef, value: Any, focused: bool) -> int:
        label_style = "heading" if focused else "muted"
        value_style = "focus" if focused else "selection"
        if field.help_text:
            help_lines = wrap_paragraph(field.help_text, max(8, w - 4))
        else:
            help_lines = []
        row = y
        row += key_value_row(
            surface,
            row,
            x,
            w,
            field.label,
            self._field_value(field, value),
            glyphs=self.glyphs,
            label_w=self._label_width(w),
            label_style=label_style,
            value_style=value_style,
            focused=focused,
        )
        for line in help_lines:
            surface.text(row, x + 2, line[: max(0, w - 4)], "muted")
            row += 1
        return row + 1

    def _draw_review_step(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        if self.wizard.operation == "install":
            rows = build_review_rows(self.install_spec, INSTALL_FIELDS)
            errors = self.install_spec.validate()
            summary = "Review the resolved install contract before starting the installer."
        else:
            rows = build_review_rows(self.uninstall_spec, UNINSTALL_FIELDS)
            errors = []
            summary = "Review the selected teardown contract before starting the uninstall run."
        row = section_heading(surface, y + 1, x + 1, w - 2, "Review", summary, glyphs=self.glyphs)
        row = titled_rule(surface, row, x + 1, w - 2, "Resolved configuration", self.glyphs, title_style="heading")
        for label, value in rows:
            used = key_value_row(
                surface,
                row,
                x + 1,
                w - 2,
                label,
                value,
                glyphs=self.glyphs,
                label_w=self._label_width(w),
                label_style="muted",
                value_style="panel",
            )
            row += used
            if row >= y + h - 6:
                break
        row += 1
        if errors:
            soft_panel(surface, row, x + 1, w - 2, errors[:3], glyphs=self.glyphs, title="Validation", line_style="error", title_style="warning")
        else:
            surface.text(row, x + 1, "Validation: ready", "success")
        preferred = self.focus.current or ("assistant:back" if errors else self._footer_action_ids()[-1])
        self.focus.set_items(self._footer_action_ids(), preferred=preferred)

    def _draw_intro_step(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        step = self._current_step()
        row = section_heading(surface, y + 1, x + 1, w - 2, step.title, step.summary, glyphs=self.glyphs)
        bullets = [
            "No destructive changes will be applied.",
            "A summary artifact is exported automatically.",
            f"Current service state: {detect_service_state()}",
        ]
        self._draw_info_block(surface, row, x + 1, w - 2, bullets, title="What this does")
        self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[-1])

    def _draw_status_step(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        status_rows = [
            ("Service state", detect_service_state()),
            ("Host", detect_host()),
            ("Arch", detect_arch()),
            ("Root dir", self.paths.root_dir),
            ("Scripts dir", self.paths.scripts_dir),
            ("Log file", self.logstore.log_path),
        ]
        row = section_heading(surface, y + 1, x + 1, w - 2, "Host Status", "", glyphs=self.glyphs)
        row = titled_rule(surface, row, x + 1, w - 2, "Detected", self.glyphs)
        for label, value in status_rows:
            row += key_value_row(
                surface,
                row,
                x + 1,
                w - 2,
                label,
                value,
                glyphs=self.glyphs,
                label_w=self._label_width(w),
            )
        surface.text(row + 1, x + 1, "Use Diagnose for deeper network and proxy checks.", "muted")
        self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[0])

    def _draw_progress_step(self, surface: CursesSurface, x: int, y: int, w: int, h: int, tier: Any) -> None:
        run = self.run_state
        row = section_heading(surface, y + 1, x + 1, w - 2, self._current_step().title, "", glyphs=self.glyphs)
        if run is None:
            surface.text(row, x + 1, "No active run.", "muted")
            self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[0])
            return
        overall = run.overall_progress
        active = run.stages.get(run.active_stage_id or "", None)
        stage_ratio = 0.0
        if active and active.total > 0:
            stage_ratio = min(1.0, max(0.0, active.current / active.total))
        bar_w = max(18, w - 2)
        progress_bar(surface, row, x + 1, bar_w, overall, glyphs=self.glyphs)
        surface.text(row + 1, x + 1, f"Overall {int(overall * 100):3d}%", "panel")
        row += 3
        row = titled_rule(surface, row, x + 1, w - 2, "Run details", self.glyphs)
        details = [
            ("Run ID", run.run_id),
            ("Status", run.status),
            ("Active stage", active.title if active else "-"),
            ("Stage progress", f"{int(stage_ratio * 100):3d}%"),
        ]
        message = active.message if active and active.message else "Working"
        for label, value in details:
            style = "primary" if label == "Status" and run.status == "running" else "panel"
            row += key_value_row(
                surface,
                row,
                x + 1,
                w - 2,
                label,
                value,
                glyphs=self.glyphs,
                label_w=self._label_width(w),
                value_style=style,
            )
        row += key_value_row(
            surface,
            row,
            x + 1,
            w - 2,
            "Message",
            message,
            glyphs=self.glyphs,
            label_w=self._label_width(w),
            value_style="muted",
        )

        available = max(0, y + h - row - 1)
        if self.ui.log_drawer_open and available >= 5:
            log_h = min(tier.log_h, available)
            log_y = y + h - log_h
            self._draw_log_drawer(surface, x + 1, log_y, w - 2, log_h)
        else:
            surface.text(y + h - 2, x + 1, "Press L to show recent logs.", "muted")
        self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[0])

    def _draw_completion_step(self, surface: CursesSurface, x: int, y: int, w: int, h: int, tier: Any) -> None:
        result = self.last_result
        title = "Completed" if result and result.status == "ok" else "Finished With Findings"
        style = "success" if result and result.status == "ok" else "warning"
        surface.text(y + 1, x + 1, title, style)
        if result is None:
            surface.text(y + 3, x + 1, "No result available.", "muted")
            self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[0])
            return
        lead = "The operation completed successfully." if result.status == "ok" else "Review the reported issues before retrying."
        row = y + 3
        for idx, line in enumerate(wrap_paragraph(lead, w - 6)):
            surface.text(row + idx, x + 1, line, "panel")
        row += len(wrap_paragraph(lead, w - 6)) + 1
        surface.text(row, x + 1, ellipsis_clip(f"Log file: {self.logstore.log_path}", max(8, w - 2), self.glyphs), "muted")
        row += 2
        if result.errors:
            row = titled_rule(surface, row, x + 1, w - 2, "Findings", self.glyphs, title_style="warning")
            for err in result.errors[:3]:
                row = soft_panel(
                    surface,
                    row,
                    x + 1,
                    w - 2,
                    [f"{err.code}: {err.message}"] + ([err.suggested_fix] if err.suggested_fix else []),
                    glyphs=self.glyphs,
                    line_style="error",
                ) + 1
        else:
            surface.text(row, x + 1, "No blocking findings were reported.", "success")
            row += 2
        if result.next_actions:
            row = self._draw_info_block(surface, row, x + 1, w - 2, result.next_actions[:3], title="Next actions")
        available = max(0, y + h - row - 1)
        if self.ui.log_drawer_open and available >= 5:
            log_h = min(tier.log_h, available)
            log_y = y + h - log_h
            self._draw_log_drawer(surface, x + 1, log_y, w - 2, log_h)
        else:
            surface.text(y + h - 3, x + 1, "Press L to show the recent log drawer.", "muted")
        self.focus.set_items(self._footer_action_ids(), preferred=self.focus.current or self._footer_action_ids()[0])

    def _draw_log_drawer(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        if h < 4:
            return
        surface.box(y, x, h, w, self.glyphs, "chrome")
        surface.text(y, x + 2, " Log ", "rail")
        filtered = self.logstore.filtered(self.ui.log_level_mask, self.ui.log_search, self.log_category_mask)
        viewport = max(1, h - 2)
        max_scroll = max(0, len(filtered) - viewport)
        self.ui.run_scroll = clamp(self.ui.run_scroll, 0, max_scroll)
        start = max(0, len(filtered) - viewport - self.ui.run_scroll)
        entries = filtered[start : start + viewport]
        for idx, entry in enumerate(entries):
            style = "panel"
            if entry.level == "warn":
                style = "warning"
            elif entry.level == "error":
                style = "error"
            elif entry.level == "debug":
                style = "muted"
            surface.text(y + 1 + idx, x + 1, entry.format_line()[: max(0, w - 2)], style)

    def _draw_footer(self, surface: CursesSurface, x: int, y: int, w: int, h: int) -> None:
        actions = self._footer_actions()
        total_w = sum(self._button_width(label) for label, _, _, _ in actions) + max(0, len(actions) - 1) * 1
        status_w = max(8, w - total_w - 8)
        surface.text(y, x + 2, ellipsis_clip(self.ui.status_line, status_w, self.glyphs), "muted")
        col = x + max(2, w - total_w - 2)
        for label, action, style, disabled in actions:
            focused = self.focus.current == action
            rect = self._draw_action_button(surface, y + 1, col, label, action, style, focused, disabled)
            self.mouse_targets.append(rect)
            col += rect.w + 1
        key_hint = "Tab cycle  Arrows move  Enter activate  Esc back  L log  Ctrl+X cancel"
        surface.text(y + 2, x + 2, ellipsis_clip(key_hint, max(8, w - 4), self.glyphs), "rail")

    def _draw_action_button(self, surface: CursesSurface, y: int, x: int, label: str, action: str, style: str, focused: bool, disabled: bool) -> Rect:
        if disabled:
            paint = "button_disabled"
        elif style == "primary":
            paint = "button_primary"
        elif style == "danger":
            paint = "button_danger"
        else:
            paint = "button"
        clipped = ellipsis_clip(label, max(4, len(label)), self.glyphs)
        text = f" {clipped} "
        marker_style = "focus" if focused and not disabled else "rail"
        left = "[" if focused and not disabled else " "
        right = "]" if focused and not disabled else " "
        if focused and not disabled and style == "secondary":
            paint = "focus"
        surface.text(y, x, left, marker_style)
        surface.text(y, x + 1, text, paint)
        surface.text(y, x + 1 + len(text), right, marker_style)
        return Rect(y=y, x=x, h=1, w=len(text) + 2, action=action)

    def _button_width(self, label: str) -> int:
        return len(f" {ellipsis_clip(label, max(4, len(label)), self.glyphs)} ") + 2

    def _footer_actions(self) -> list[tuple[str, str, str, bool]]:
        if self.ui.mode == "welcome":
            return [
                ("Quit", "welcome:action:quit", "secondary", False),
                ("Continue", "welcome:action:continue", "primary", False),
            ]

        step = self._current_step()
        if step.kind == "progress":
            running = bool(self.run_thread and self.run_thread.is_alive())
            label = "Hide Log" if self.ui.log_drawer_open else "Show Log"
            return [
                (label, "assistant:toggle-log", "secondary", False),
                ("Cancel", "assistant:cancel-run", "danger", not running),
            ]
        if step.kind == "completion":
            label = "Hide Log" if self.ui.log_drawer_open else "Show Log"
            return [
                (label, "assistant:toggle-log", "secondary", False),
                ("Retry", "assistant:retry", "secondary", False),
                ("Home", "assistant:home", "primary", False),
            ]
        if step.kind == "status":
            return [
                ("Diagnose", "assistant:diagnose", "secondary", False),
                ("Back", "assistant:back", "primary", False),
            ]
        if step.kind == "intro":
            return [
                ("Back", "assistant:back", "secondary", False),
                ("Run", "assistant:run", "primary", False),
            ]
        if step.kind == "review":
            invalid = self.wizard.operation == "install" and bool(self.install_spec.validate())
            run_label = "Install" if self.wizard.operation == "install" else "Uninstall"
            return [
                ("Back", "assistant:back", "secondary", False),
                (run_label, "assistant:run", "primary", invalid),
            ]
        return [
            ("Back", "assistant:back", "secondary", False),
            ("Continue", "assistant:continue", "primary", False),
        ]

    def _footer_action_ids(self) -> list[str]:
        return [action for _, action, _, _ in self._footer_actions()]

    def _action_disabled(self, action_id: str) -> bool:
        for _, action, _, disabled in self._footer_actions():
            if action == action_id:
                return disabled
        return False

    def _current_step(self) -> AssistantStep:
        flow = operation_flow(self.wizard.operation)
        idx = clamp(self.wizard.step_idx, 0, len(flow) - 1)
        self.wizard.step_idx = idx
        return flow[idx]

    def _current_values(self) -> Any:
        return self.install_spec if self.wizard.operation == "install" else self.uninstall_spec

    def _field_value(self, field: FieldDef, value: Any) -> str:
        if field.ftype == "bool":
            return "Enabled" if bool(value) else "Disabled"
        shown = str(value or "")
        return shown if shown else "(empty)"

    def _handle_key(self, key: object) -> None:
        if key == curses.KEY_MOUSE:
            self._handle_mouse()
            return
        key_tab = getattr(curses, "KEY_TAB", None)
        if key in ("\t", 9) or (isinstance(key_tab, int) and key == key_tab):
            self.focus.next()
            return
        if key == curses.KEY_BTAB:
            self.focus.prev()
            return
        if key == "\x18":
            self._cancel_run()
            return
        if key in ("q", "Q") and self.ui.mode == "welcome":
            self.running = False
            return
        if key == "L" and self.ui.mode == "assistant" and self._current_step().kind in {"progress", "completion"}:
            self.ui.log_drawer_open = not self.ui.log_drawer_open
            self.ui.status_line = "Log drawer shown." if self.ui.log_drawer_open else "Log drawer hidden."
            return
        if key in (curses.KEY_NPAGE,) and self.ui.mode == "assistant" and self._current_step().kind in {"progress", "completion"}:
            self.ui.run_scroll = max(0, self.ui.run_scroll - 8)
            return
        if key in (curses.KEY_PPAGE,) and self.ui.mode == "assistant" and self._current_step().kind in {"progress", "completion"}:
            self.ui.run_scroll += 8
            return
        if key in (curses.KEY_UP, "k"):
            self._handle_vertical(-1)
            return
        if key in (curses.KEY_DOWN, "j"):
            self._handle_vertical(1)
            return
        if key in (curses.KEY_LEFT, "h"):
            self._handle_horizontal(-1)
            return
        if key in (curses.KEY_RIGHT, "l"):
            self._handle_horizontal(1)
            return
        if key in ("\x1b", 27, curses.KEY_EXIT):
            self._handle_escape()
            return
        if key in (10, 13, curses.KEY_ENTER, "\n", " "):
            self._activate_focus(self.focus.current)

    def _handle_vertical(self, delta: int) -> None:
        cur = self.focus.current
        if self.ui.mode == "welcome":
            if cur.startswith("welcome:card:"):
                self.selected_operation = clamp(int(cur.rsplit(":", 1)[1]) + delta, 0, len(OPERATIONS) - 1)
                self.focus.set_items(self.focus.items, preferred=f"welcome:card:{self.selected_operation}")
            return
        step = self._current_step()
        if step.kind == "form":
            names = visible_fields(self.wizard.operation, step, self._current_values())
            if not names:
                return
            self.wizard.field_idx = clamp(self.wizard.field_idx + delta, 0, len(names) - 1)
            self.focus.set_items(self.focus.items, preferred=f"field:{names[self.wizard.field_idx]}")

    def _handle_horizontal(self, delta: int) -> None:
        cur = self.focus.current
        if cur.startswith("field:"):
            name = cur.split(":", 1)[1]
            field = field_def(self.wizard.operation, name)
            if field is None:
                return
            if field.ftype == "bool":
                self._toggle_field(field)
                return
            if field.ftype == "choice":
                self._cycle_choice(field, delta)
                return
        action_ids = self._footer_action_ids()
        if cur in action_ids:
            idx = clamp(action_ids.index(cur) + delta, 0, len(action_ids) - 1)
            self.focus.set_items(self.focus.items, preferred=action_ids[idx])

    def _handle_escape(self) -> None:
        if self.ui.mode == "assistant" and self._current_step().kind == "progress" and self.run_thread and self.run_thread.is_alive():
            self.ui.status_line = "Run is active. Use Ctrl+X or Cancel."
            return
        if self.ui.mode == "assistant":
            self._go_back()

    def _handle_mouse(self) -> None:
        try:
            _, mx, my, _, _ = curses.getmouse()
        except Exception:
            return
        for rect in self.mouse_targets:
            if rect.contains(my, mx):
                self._activate_focus(rect.action)
                return

    def _activate_focus(self, focus_id: str) -> None:
        if not focus_id:
            return
        if focus_id.startswith("assistant:") and self._action_disabled(focus_id):
            self.ui.status_line = "That action is unavailable until the current issues are resolved."
            return
        if focus_id.startswith("welcome:"):
            self._activate_welcome(focus_id)
            return
        if focus_id.startswith("field:"):
            self._activate_field(focus_id.split(":", 1)[1])
            return
        if focus_id.startswith("assistant:"):
            self._activate_action(focus_id)

    def _activate_welcome(self, focus_id: str) -> None:
        if focus_id.startswith("welcome:card:"):
            self.selected_operation = clamp(int(focus_id.rsplit(":", 1)[1]), 0, len(OPERATIONS) - 1)
            self.focus.set_items(self.focus.items, preferred=focus_id)
            return
        if focus_id == "welcome:action:quit":
            self.running = False
            return
        if focus_id == "welcome:action:continue":
            meta = OPERATIONS[self.selected_operation]
            self.wizard = WizardState(operation=meta.key, step_idx=0, field_idx=0)
            self.ui.mode = "assistant"
            self.ui.log_drawer_open = False
            self.ui.status_line = f"Selected: {meta.title}"
            self.focus.set_items([], preferred=None)

    def _activate_field(self, name: str) -> None:
        field = field_def(self.wizard.operation, name)
        if field is None:
            return
        if field.ftype == "bool":
            self._toggle_field(field)
            return
        if field.ftype == "choice":
            selected = self._select_choice(field.label, list(field.options), str(getattr(self._current_values(), field.name)))
            if selected is None:
                self.ui.status_line = f"{field.label} unchanged."
                return
            setattr(self._current_values(), field.name, selected)
            self._after_install_mutation(field.name)
            self.ui.status_line = f"{field.label} set to {selected}"
            return
        current = str(getattr(self._current_values(), field.name))
        value = self._prompt_line(field.label, current)
        if value is None:
            self.ui.status_line = f"{field.label} unchanged."
            return
        setattr(self._current_values(), field.name, value)
        self._after_install_mutation(field.name)
        self.ui.status_line = f"{field.label} updated."

    def _activate_action(self, focus_id: str) -> None:
        if focus_id == "assistant:back":
            self._go_back()
            return
        if focus_id == "assistant:continue":
            self._go_next()
            return
        if focus_id == "assistant:run":
            self._start_run(self.wizard.operation)
            return
        if focus_id == "assistant:toggle-log":
            self.ui.log_drawer_open = not self.ui.log_drawer_open
            self.ui.status_line = "Log drawer shown." if self.ui.log_drawer_open else "Log drawer hidden."
            return
        if focus_id == "assistant:cancel-run":
            self._cancel_run()
            return
        if focus_id == "assistant:retry":
            self._start_run(self.wizard.operation)
            return
        if focus_id == "assistant:home":
            self.ui.mode = "welcome"
            self.ui.log_drawer_open = False
            self.ui.status_line = "Back to welcome."
            self.focus.set_items([], preferred=None)
            return
        if focus_id == "assistant:diagnose":
            self.wizard = WizardState(operation="diagnose", step_idx=0, field_idx=0)
            self.ui.mode = "assistant"
            self.ui.log_drawer_open = False
            self.ui.status_line = "Diagnostics ready."

    def _go_back(self) -> None:
        if self.ui.mode != "assistant":
            return
        step = self._current_step()
        if step.kind in {"completion", "status"}:
            self.ui.mode = "welcome"
            self.ui.log_drawer_open = False
            self.ui.status_line = "Back to welcome."
            self.focus.set_items([], preferred=None)
            return
        if self.wizard.step_idx <= 0:
            self.ui.mode = "welcome"
            self.ui.status_line = "Back to welcome."
            self.focus.set_items([], preferred=None)
            return
        self.wizard.step_idx -= 1
        self.wizard.field_idx = 0
        self.ui.status_line = f"Back to {self._current_step().title}."
        self.focus.set_items([], preferred=None)

    def _go_next(self) -> None:
        flow = operation_flow(self.wizard.operation)
        self.wizard.step_idx = clamp(self.wizard.step_idx + 1, 0, len(flow) - 1)
        self.wizard.field_idx = 0
        self.ui.status_line = self._current_step().title
        self.focus.set_items([], preferred=None)

    def _toggle_field(self, field: FieldDef) -> None:
        obj = self._current_values()
        current = bool(getattr(obj, field.name))
        next_value = not current
        if field.name in {"install_service", "proxy_setup"} and not next_value:
            confirmed = self._confirm_dialog(
                ConfirmModal(
                    title=f"Disable {field.label}?",
                    detail="This may prevent service startup or external access.",
                    cancel_label="Keep Enabled",
                    confirm_label="Disable",
                )
            )
            if not confirmed:
                self.ui.status_line = f"{field.label} unchanged."
                return
        setattr(obj, field.name, next_value)
        self._after_install_mutation(field.name)
        self.ui.status_line = f"{field.label} set to {'Enabled' if next_value else 'Disabled'}"

    def _cycle_choice(self, field: FieldDef, delta: int) -> None:
        options = list(field.options)
        if not options:
            return
        obj = self._current_values()
        current = str(getattr(obj, field.name))
        idx = options.index(current) if current in options else 0
        idx = clamp(idx + delta, 0, len(options) - 1)
        setattr(obj, field.name, options[idx])
        self._after_install_mutation(field.name)
        self.ui.status_line = f"{field.label} set to {options[idx]}"

    def _after_install_mutation(self, field_name: str) -> None:
        if self.wizard.operation != "install":
            return
        if field_name not in {"proxy_setup", "proxy_tls", "proxy_server_name", "base_domain", "proxy_cert", "proxy_key", "dovecot_auth_mode"}:
            return
        before = (self.install_spec.proxy_cert, self.install_spec.proxy_key)
        if _autofill_proxy_tls_paths(self.install_spec):
            after = (self.install_spec.proxy_cert, self.install_spec.proxy_key)
            if after != before:
                self.ui.status_line = "Auto-detected TLS cert/key from /etc/letsencrypt/live."

    def _cancel_run(self) -> None:
        if self.run_thread and self.run_thread.is_alive() and self.cancel_token is not None:
            self.cancel_token.cancel()
            self.ui.status_line = "Cancelling active run..."
            return
        self.ui.status_line = "No active run to cancel."

    def _prompt_line(self, label: str, initial: str) -> str | None:
        h, w = self.stdscr.getmaxyx()
        win_h = 7
        win_w = max(60, int(w * 0.72))
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        buf = list(initial)
        cur = len(buf)
        self.stdscr.timeout(-1)
        curses.curs_set(1)
        try:
            while True:
                surface = CursesSurface(self.stdscr, self.theme)
                surface.box(y, x, win_h, win_w, self.glyphs, "chrome")
                surface.text(y, x + 2, f" {label} ", "rail")
                surface.text(y + 1, x + 2, "Enter save  ·  Esc cancel  ·  Ctrl+U clear", "muted")
                max_len = win_w - 4
                text = "".join(buf)
                if len(text) <= max_len:
                    display = text
                    offset = 0
                else:
                    offset = max(0, cur - max_len)
                    display = text[offset : offset + max_len]
                surface.fill(y + 3, x + 2, 1, max_len, " ", "panel")
                surface.text(y + 3, x + 2, display, "panel")
                cursor_col = x + 2 + max(0, min(max_len - 1, cur - offset))
                self.stdscr.move(y + 3, cursor_col)
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if key in (10, 13, curses.KEY_ENTER, "\n"):
                    return "".join(buf).strip()
                if key in ("\x1b", 27, curses.KEY_EXIT):
                    return None
                if key == "\x15":
                    buf = []
                    cur = 0
                    continue
                if key in (curses.KEY_LEFT,):
                    cur = max(0, cur - 1)
                    continue
                if key in (curses.KEY_RIGHT,):
                    cur = min(len(buf), cur + 1)
                    continue
                if key == curses.KEY_HOME:
                    cur = 0
                    continue
                if key == curses.KEY_END:
                    cur = len(buf)
                    continue
                if key == curses.KEY_DC and cur < len(buf):
                    del buf[cur]
                    continue
                if key in (curses.KEY_BACKSPACE, 127, 8, "\x7f", "\b"):
                    if cur > 0:
                        cur -= 1
                        del buf[cur]
                    continue
                if isinstance(key, str) and key.isprintable() and len(buf) < 2048:
                    buf.insert(cur, key)
                    cur += 1
        finally:
            self.stdscr.timeout(120)
            curses.curs_set(0)

    def _select_choice(self, label: str, options: list[str], current: str) -> str | None:
        if not options:
            return None
        h, w = self.stdscr.getmaxyx()
        win_h = min(max(10, len(options) + 5), h - 2)
        win_w = min(max(44, len(label) + 14), w - 4)
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        idx = options.index(current) if current in options else 0
        top = 0
        self.stdscr.timeout(-1)
        try:
            while True:
                surface = CursesSurface(self.stdscr, self.theme)
                surface.box(y, x, win_h, win_w, self.glyphs, "chrome")
                surface.text(y, x + 2, f" {label} ", "rail")
                viewport = win_h - 4
                if idx < top:
                    top = idx
                if idx >= top + viewport:
                    top = idx - viewport + 1
                for row in range(viewport):
                    opt_i = top + row
                    ly = y + 2 + row
                    surface.fill(ly, x + 2, 1, win_w - 4, " ", "panel")
                    if opt_i >= len(options):
                        continue
                    opt = options[opt_i]
                    style = "focus" if opt_i == idx else "panel"
                    surface.text(ly, x + 2, opt[: win_w - 5], style)
                surface.text(y + win_h - 2, x + 2, "Arrows move  ·  Enter select  ·  Esc cancel", "muted")
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if key in (curses.KEY_DOWN, "j"):
                    idx = clamp(idx + 1, 0, len(options) - 1)
                    continue
                if key in (curses.KEY_UP, "k"):
                    idx = clamp(idx - 1, 0, len(options) - 1)
                    continue
                if key in (curses.KEY_NPAGE,):
                    idx = clamp(idx + viewport, 0, len(options) - 1)
                    continue
                if key in (curses.KEY_PPAGE,):
                    idx = clamp(idx - viewport, 0, len(options) - 1)
                    continue
                if key in (10, 13, curses.KEY_ENTER, "\n"):
                    return options[idx]
                if key in ("\x1b", 27, curses.KEY_EXIT):
                    return None
        finally:
            self.stdscr.timeout(120)

    def _confirm_dialog(self, modal: ConfirmModal) -> bool:
        h, w = self.stdscr.getmaxyx()
        win_h = 9
        win_w = min(max(64, len(modal.detail) + 8), w - 4)
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        selected = 0
        self.stdscr.timeout(-1)
        try:
            while True:
                surface = CursesSurface(self.stdscr, self.theme)
                surface.box(y, x, win_h, win_w, self.glyphs, "chrome")
                surface.text(y, x + 2, " Confirm ", "rail")
                surface.text(y + 1, x + 2, modal.title[: win_w - 4], "heading")
                surface.text(y + 3, x + 2, modal.detail[: win_w - 4], "panel")
                r_cancel = self._draw_action_button(surface, y + 6, x + 2, modal.cancel_label, "modal:cancel", "secondary", selected == 0, False)
                r_confirm = self._draw_action_button(surface, y + 6, x + 20, modal.confirm_label, "modal:confirm", "primary", selected == 1, False)
                surface.text(y + 7, x + 2, "Left/Right select  ·  Enter confirm  ·  Esc cancel", "muted")
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if key == curses.KEY_MOUSE:
                    try:
                        _, mx, my, _, _ = curses.getmouse()
                        if r_cancel.contains(my, mx):
                            return False
                        if r_confirm.contains(my, mx):
                            return True
                    except Exception:
                        pass
                    continue
                if key in (curses.KEY_LEFT, "h", "\t", curses.KEY_BTAB):
                    selected = 0
                    continue
                if key in (curses.KEY_RIGHT, "l"):
                    selected = 1
                    continue
                if key in (10, 13, curses.KEY_ENTER, "\n"):
                    return selected == 1
                if key in ("\x1b", 27, curses.KEY_EXIT):
                    return False
        finally:
            self.stdscr.timeout(120)

    def _start_run(self, operation: str) -> None:
        if self.run_thread and self.run_thread.is_alive():
            self.ui.status_line = "A run is already in progress."
            return
        stage_defs = INSTALL_STAGE_DEFS
        if operation == "uninstall":
            stage_defs = UNINSTALL_STAGE_DEFS
        elif operation == "diagnose":
            stage_defs = DIAG_STAGE_DEFS
        run_id = f"local-{int(time.time())}"
        self.run_state = new_run_state(operation, run_id, stage_defs)
        self.active_operation = operation
        self.last_result = None
        self.last_summary_payload = {}
        self.ui.run_scroll = 0
        self.ui.log_drawer_open = False
        self.wizard.operation = operation  # type: ignore[assignment]
        self.wizard.step_idx = _PROGRESS_STAGE_INDEX.get(operation, 0)
        self.ui.mode = "assistant"
        self.ui.status_line = f"Running {operation}..."

        if operation == "install":
            _autofill_proxy_tls_paths(self.install_spec)
            preflight_error = self._check_install_preflight()
            if preflight_error is not None:
                apply_runner_event(self.run_state, {"type": "run_start", "run_id": run_id, "operation": operation})
                apply_runner_event(self.run_state, {"type": "stage_start", "stage_id": "preflight", "message": "started"})
                apply_runner_event(self.run_state, {"type": "stage_result", "stage_id": "preflight", "status": "failed", "error_code": "E_PREFLIGHT"})
                apply_runner_event(self.run_state, {"type": "run_result", "status": "failed", "failed_stage": "preflight", "exit_code": "1"})
                self.logstore.append("error", "preflight", preflight_error.message, category="system")
                self.last_result = OperationResult(
                    status="failed",
                    errors=[preflight_error],
                    artifacts={"full_log": str(self.logstore.log_path)},
                    next_actions=[
                        "Run as root, or pre-authorize sudo: sudo -v",
                        "Then restart despatch.py and run install again.",
                    ],
                )
                self.last_summary_payload = self._build_summary_payload(operation, self.last_result)
                self.logstore.export_summary(self.last_summary_payload)
                self.wizard.step_idx = _COMPLETION_STAGE_INDEX.get(operation, self.wizard.step_idx)
                self.ui.status_line = preflight_error.message
                return

        self.cancel_token = CancelToken()

        def emit(evt: dict[str, Any]) -> None:
            self.events.put(evt)

        def worker() -> None:
            if operation == "install":
                result = self.runner.run_install(self.install_spec, self.logstore, self.cancel_token or CancelToken(), emit)
            elif operation == "uninstall":
                result = self.runner.run_uninstall(self.uninstall_spec, self.logstore, self.cancel_token or CancelToken(), emit)
            else:
                result = self.runner.run_diagnose(DiagnoseSpec(), self.logstore, self.cancel_token or CancelToken(), emit)
            self.last_result = result
            payload = self._build_summary_payload(operation, result)
            self.last_summary_payload = payload
            summary = self.logstore.export_summary(payload)
            self.events.put({"type": "log", "level": "info", "category": "system", "stage_id": "summary", "message": f"Summary exported: {summary}"})

        self.run_thread = threading.Thread(target=worker, daemon=True)
        self.run_thread.start()
        self.focus.set_items([], preferred=None)

    def _drain_events(self) -> None:
        while True:
            try:
                evt = self.events.get_nowait()
            except queue.Empty:
                break
            if self.run_state is None:
                continue
            etype = evt.get("type", "")
            if etype == "log":
                msg = str(evt.get("message", ""))
                if msg:
                    self.ui.status_line = msg[:120]
                continue
            apply_runner_event(self.run_state, evt)
            if etype == "run_result":
                status = str(evt.get("status", ""))
                self.wizard.step_idx = _COMPLETION_STAGE_INDEX.get(self.wizard.operation, self.wizard.step_idx)
                if status == "ok":
                    self.ui.status_line = "Run completed successfully."
                elif status == "cancelled":
                    self.ui.status_line = "Run cancelled."
                else:
                    self.ui.status_line = f"Run failed in stage {self.run_state.failed_stage or 'unknown'}."

    def _check_install_preflight(self) -> RunnerError | None:
        if os.geteuid() == 0:
            return None
        if not self._command_exists("sudo"):
            return RunnerError(
                code="E_PREFLIGHT",
                message="Install requires root privileges or sudo, but sudo is unavailable.",
                stage_id="preflight",
                suggested_fix="Run the TUI as root.",
            )
        probe = None
        try:
            probe = __import__("subprocess").run(["sudo", "-n", "true"], capture_output=True, text=True, timeout=4, check=False)
        except Exception as exc:
            return RunnerError(
                code="E_PREFLIGHT",
                message=f"Failed privilege preflight: {exc}",
                stage_id="preflight",
                suggested_fix="Run as root or refresh sudo credentials.",
            )
        if probe and probe.returncode == 0:
            return None
        return RunnerError(
            code="E_PREFLIGHT",
            message="Install requires root privileges. sudo -n failed (no cached credentials).",
            stage_id="preflight",
            suggested_fix="Run 'sudo -v' first, or launch despatch.py as root.",
        )

    @staticmethod
    def _command_exists(name: str) -> bool:
        return any(os.access(os.path.join(path, name), os.X_OK) for path in os.environ.get("PATH", "").split(os.pathsep) if path)

    def _build_summary_payload(self, operation: str, result: OperationResult) -> dict[str, Any]:
        failing_invariant = ""
        if result.errors:
            failing_invariant = f"{result.errors[0].code}: {result.errors[0].message}"
        return {
            "status": result.status,
            "operation": operation,
            "errors": [e.__dict__ for e in result.errors],
            "artifacts": result.artifacts,
            "next_actions": result.next_actions,
            "failing_invariant": failing_invariant,
            "spec_snapshot": self._spec_snapshot(operation),
            "ts": time.time(),
        }

    def _spec_snapshot(self, operation: str) -> dict[str, Any]:
        if operation == "install":
            raw = dict(self.install_spec.__dict__)
        elif operation == "uninstall":
            raw = dict(self.uninstall_spec.__dict__)
        else:
            raw = {}
        for key in ("dovecot_auth_db_dsn", "proxy_key"):
            if key in raw and raw[key]:
                raw[key] = "***REDACTED***"
        return raw


def run_curses_main(stdscr: curses.window) -> None:
    DespatchTUI(stdscr).run()


class _PreviewWindow:
    def __init__(self, width: int, height: int) -> None:
        self._width = width
        self._height = height

    def getmaxyx(self) -> tuple[int, int]:
        return (self._height, self._width)


def _preview_tui(width: int, height: int, *, ascii_mode: bool = False) -> DespatchTUI:
    tui = DespatchTUI(_PreviewWindow(width, height))
    tui.theme = Theme(has_color=False)
    tui.glyphs = ASCII_GLYPHS if ascii_mode else UNICODE_GLYPHS
    tui.ui.status_line = f"Ready. Log file: {tui.logstore.log_path}"
    return tui


def _render_preview(tui: DespatchTUI, width: int, height: int) -> list[str]:
    surface = BufferSurface(width, height)
    tui._draw_shell(surface)  # type: ignore[arg-type]
    return surface.render()


def _step_index(operation: Operation, step_key: str) -> int:
    flow = operation_flow(operation)
    for idx, step in enumerate(flow):
        if step.key == step_key:
            return idx
    raise ValueError(f"unknown step {operation}:{step_key}")


def render_welcome_preview(width: int, height: int, ascii_mode: bool = False) -> list[str]:
    tui = _preview_tui(width, height, ascii_mode=ascii_mode)
    tui.ui.mode = "welcome"
    tui.selected_operation = 0
    return _render_preview(tui, width, height)


def render_form_preview(width: int, height: int, step_key: str, ascii_mode: bool = False) -> list[str]:
    tui = _preview_tui(width, height, ascii_mode=ascii_mode)
    tui.ui.mode = "assistant"
    tui.wizard = WizardState(operation="install", step_idx=_step_index("install", step_key), field_idx=0)
    tui.install_spec.base_domain = "mail.2h4s2d.ru"
    tui.install_spec.listen_addr = ":8080"
    tui.install_spec.proxy_setup = True
    tui.install_spec.proxy_server = "apache2"
    tui.install_spec.proxy_server_name = "mail.2h4s2d.ru"
    tui.install_spec.proxy_tls = True
    tui.install_spec.proxy_cert = "/etc/letsencrypt/live/mail.2h4s2d.ru/fullchain.pem"
    tui.install_spec.proxy_key = "/etc/letsencrypt/live/mail.2h4s2d.ru/privkey.pem"
    tui.install_spec.dovecot_auth_mode = "pam"
    tui.focus.set_items([f"field:{visible_fields('install', tui._current_step(), tui.install_spec)[0]}"], preferred=None)
    return _render_preview(tui, width, height)


def render_review_preview(width: int, height: int, ascii_mode: bool = False, *, long_values: bool = False) -> list[str]:
    tui = _preview_tui(width, height, ascii_mode=ascii_mode)
    tui.ui.mode = "assistant"
    tui.wizard = WizardState(operation="install", step_idx=_step_index("install", "review"), field_idx=0)
    tui.install_spec.base_domain = "mail.2h4s2d.ru"
    tui.install_spec.proxy_server = "apache2"
    tui.install_spec.proxy_server_name = "mail.2h4s2d.ru"
    tui.install_spec.proxy_setup = True
    tui.install_spec.proxy_tls = True
    tui.install_spec.proxy_cert = (
        "/etc/letsencrypt/live/mail.2h4s2d.ru/fullchain.pem"
        if not long_values
        else "/etc/letsencrypt/live/really.long.example.mail.2h4s2d.ru/with/a/deep/path/fullchain.pem"
    )
    tui.install_spec.proxy_key = (
        "/etc/letsencrypt/live/mail.2h4s2d.ru/privkey.pem"
        if not long_values
        else "/etc/letsencrypt/live/really.long.example.mail.2h4s2d.ru/with/a/deep/path/privkey.pem"
    )
    tui.install_spec.dovecot_auth_db_dsn = (
        ""
        if not long_values
        else "host=db.internal.example port=5432 user=despatch password=secret dbname=despatch sslmode=disable"
    )
    return _render_preview(tui, width, height)


def render_progress_preview(width: int, height: int, log_open: bool = False, ascii_mode: bool = False) -> list[str]:
    tui = _preview_tui(width, height, ascii_mode=ascii_mode)
    tui.ui.mode = "assistant"
    tui.ui.log_drawer_open = log_open
    tui.wizard = WizardState(operation="install", step_idx=_PROGRESS_STAGE_INDEX["install"], field_idx=0)
    tui.run_state = new_run_state("install", "31458ff8-9adc-4b81-9eee-dd554ddae2e0", INSTALL_STAGE_DEFS)
    apply_runner_event(tui.run_state, {"type": "stage_result", "stage_id": "preflight", "status": "ok", "error_code": ""})
    apply_runner_event(tui.run_state, {"type": "stage_result", "stage_id": "fetch_source", "status": "ok", "error_code": ""})
    apply_runner_event(tui.run_state, {"type": "stage_start", "stage_id": "build", "message": "started"})
    apply_runner_event(tui.run_state, {"type": "stage_progress", "stage_id": "build", "current": "0", "total": "1", "message": "started"})
    tui.ui.status_line = "warning: function `request_queue_path` is never used"
    tui.logstore.append("info", "system", "stage running", category="system")
    return _render_preview(tui, width, height)


def render_completion_preview(width: int, height: int, log_open: bool = False, ascii_mode: bool = False) -> list[str]:
    tui = _preview_tui(width, height, ascii_mode=ascii_mode)
    tui.ui.mode = "assistant"
    tui.ui.log_drawer_open = log_open
    tui.wizard = WizardState(operation="diagnose", step_idx=_COMPLETION_STAGE_INDEX["diagnose"], field_idx=0)
    tui.last_result = OperationResult(
        status="ok",
        next_actions=["Open web UI and verify OOBE/mail access."],
    )
    tui.ui.status_line = "Log drawer shown." if log_open else "Ready."
    tui.logstore.append("info", "system", "Status: inactive", category="system")
    tui.logstore.append("info", "network", "Healthy: Internet access path looks good.", category="network")
    return _render_preview(tui, width, height)
