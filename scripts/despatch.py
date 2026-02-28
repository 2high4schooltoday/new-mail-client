#!/usr/bin/env python3
"""Despatch TUI: widget-driven installer/uninstaller dashboard (stdlib only)."""

from __future__ import annotations

import curses
import curses.ascii
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REMOTE_BASE = "https://raw.githubusercontent.com/2high4schooltoday/new-mail-client/main/scripts/tui"


def _bootstrap_tui_modules() -> None:
    try:
        import tui.models  # noqa: F401

        return
    except Exception:
        pass

    cache_root = Path.home() / ".cache" / "mailclient-tui" / "modules"
    module_dir = cache_root / "tui"
    module_dir.mkdir(parents=True, exist_ok=True)
    files = [
        "__init__.py",
        "models.py",
        "state.py",
        "runner.py",
        "system_ops.py",
        "views.py",
        "keys.py",
        "logstore.py",
        "theme.py",
        "focus.py",
        "widgets.py",
        "screens.py",
        "modals.py",
    ]
    for filename in files:
        url = f"{REMOTE_BASE}/{filename}"
        target = module_dir / filename
        try:
            urllib.request.urlretrieve(url, target)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to bootstrap TUI module {filename} from {url}: {exc}"
            ) from exc
    sys.path.insert(0, str(cache_root))


_bootstrap_tui_modules()

from tui.focus import FocusState
from tui.keys import is_backspace, is_enter
from tui.logstore import LogStore
from tui.modals import ConfirmModal
from tui.models import (
    DIAG_STAGE_DEFS,
    INSTALL_STAGE_DEFS,
    UNINSTALL_STAGE_DEFS,
    DiagnoseSpec,
    InstallSpec,
    OperationResult,
    RunnerError,
    RunState,
    UninstallSpec,
)
from tui.runner import OperationRunner
from tui.screens import (
    FIELD_INDEX_INSTALL,
    FIELD_INDEX_UNINSTALL,
    INSTALL_FIELDS,
    INSTALL_STEPS,
    UNINSTALL_FIELDS,
    UNINSTALL_STEPS,
    FieldDef,
    OperationCard,
    WizardStep,
    build_review_lines,
)
from tui.state import UIState, apply_runner_event, new_run_state
from tui.system_ops import (
    AppPaths,
    CancelToken,
    detect_arch,
    detect_host,
    detect_paths,
    detect_proxy_candidates,
    detect_service_state,
)
from tui.theme import Theme
from tui.views import clamp, draw_box, safe_addstr, spinner
from tui.widgets import Rect, draw_badge, draw_button, draw_meter, draw_segmented, draw_toggle


STAGE_META: dict[str, tuple[str, str]] = {
    "preflight": ("[P]", "info"),
    "fetch_source": ("[F]", "info"),
    "deps": ("[D]", "warning"),
    "build": ("[B]", "info"),
    "filesystem_and_user": ("[FS]", "info"),
    "env_generation": ("[ENV]", "info"),
    "service_install_start": ("[SVC]", "primary"),
    "firewall": ("[FW]", "warning"),
    "proxy": ("[PX]", "warning"),
    "post_checks": ("[CHK]", "primary"),
    "final_summary": ("[SUM]", "info"),
    "backups": ("[BAK]", "info"),
    "service": ("[SVC]", "warning"),
    "cleanup": ("[CLN]", "warning"),
    "summary": ("[SUM]", "info"),
    "diagnostics": ("[DOC]", "primary"),
}


@dataclass
class EditorState:
    operation: str
    step_idx: int = 0
    row_idx: int = 0


class DespatchTUI:
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr = stdscr
        self.ui = UIState()
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
        self.uninstall_spec = UninstallSpec()

        self.mode = "home"
        self.selected_operation = 0
        self.editor: EditorState | None = None
        self.focus = FocusState()
        self.theme = Theme(has_color=False)
        self.mouse_targets: list[Rect] = []
        self.log_category_mask: set[str] = {"system", "network", "proxy", "service", "auth"}
        self.log_level_order = ["debug", "info", "warn", "error"]
        self.ui.status_line = f"Ready. Log file: {self.logstore.log_path}"
        self.running = True

        self.cards = [
            OperationCard(
                "install",
                "Install / Upgrade",
                "Install Despatch with staged verification and post-checks.",
                "LOW",
                "Requires root or sudo credentials.",
            ),
            OperationCard(
                "uninstall",
                "Uninstall",
                "Safe removal with controlled backup and cleanup toggles.",
                "HIGH",
                "Review destructive cleanup toggles before run.",
                danger=True,
            ),
            OperationCard(
                "diagnose",
                "Diagnose",
                "Run deployment/access diagnostics and collect findings.",
                "LOW",
                "No destructive system changes.",
            ),
            OperationCard(
                "status",
                "Status",
                "Inspect service state and environment quickly.",
                "LOW",
                "Read-only status dashboard.",
            ),
        ]

    def run(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(False)
        self.stdscr.timeout(120)
        self.stdscr.keypad(True)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        os.environ.setdefault("ESCDELAY", "25")
        self.theme = Theme.init()

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
            safe_addstr(self.stdscr, 0, 0, "Terminal too small. Resize to at least 96x24.", self.theme.attrs.error)
            self.stdscr.refresh()
            return
        self._draw_header(w)
        body_y = 3
        body_h = h - 7

        if self.mode == "home":
            self._draw_home(body_y, body_h, w)
        elif self.mode in {"install_editor", "uninstall_editor"}:
            self._draw_editor(body_y, body_h, w)
        elif self.mode == "run":
            self._draw_run_dashboard(body_y, body_h, w)
        elif self.mode == "status":
            self._draw_status(body_y, body_h, w)

        self._draw_footer(h - 3, w)
        self.stdscr.refresh()

    def _draw_header(self, w: int) -> None:
        safe_addstr(self.stdscr, 0, 2, "DESPATCH :: CONTROL PANEL", self.theme.attrs.heading)
        badge = f"service:{detect_service_state()} host:{detect_host()} arch:{detect_arch()}"
        safe_addstr(self.stdscr, 1, 2, badge, self.theme.attrs.info)
        draw_badge(self.stdscr, self.theme, 1, max(2, w - 24), self.mode.replace("_", " ").upper(), "primary")

    def _draw_footer(self, y: int, w: int) -> None:
        draw_box(self.stdscr, y, 0, 3, w, " ACTIONS ", self.theme.attrs.panel)
        if self.mode == "home":
            keys = "Tab focus | Enter/Space activate | Arrows navigate | q quit"
        elif self.mode in {"install_editor", "uninstall_editor"}:
            keys = "Tab focus | Arrows move/select | Enter edit/toggle | Esc back | F5 run"
        elif self.mode == "run":
            keys = "F5 rerun | F9 diagnose | / search logs | PgUp/PgDn scroll | Tab focus"
        else:
            keys = "Tab focus | Enter activate | Esc back"
        safe_addstr(self.stdscr, y + 1, 2, keys, self.theme.attrs.muted)
        safe_addstr(self.stdscr, y + 1, max(2, w - min(70, w - 4)), self.ui.status_line[: max(0, w - 6)], self.theme.attrs.muted)

    def _draw_home(self, y: int, h: int, w: int) -> None:
        left_w = max(36, int(w * 0.42))
        right_w = w - left_w
        draw_box(self.stdscr, y, 0, h, left_w, " HOME :: OPERATIONS ", self.theme.attrs.panel)
        draw_box(self.stdscr, y, left_w, h, right_w, " DETAILS ", self.theme.attrs.panel)

        items: list[str] = []
        row = y + 2
        for idx, card in enumerate(self.cards):
            fid = f"home:op:{idx}"
            items.append(fid)
            focused = self.focus.current == fid
            selected = idx == self.selected_operation
            attr = self.theme.attrs.focus if focused else (self.theme.attrs.primary if selected else 0)
            safe_addstr(self.stdscr, row, 2, f"{card.title}", attr)
            risk_kind = "error" if card.risk == "HIGH" else "warning" if card.risk == "MEDIUM" else "info"
            draw_badge(self.stdscr, self.theme, row, max(2, left_w - 12), card.risk, risk_kind)
            row += 2
            self.mouse_targets.append(Rect(row - 2, 2, 1, left_w - 4, fid))

        selected = self.cards[self.selected_operation]
        safe_addstr(self.stdscr, y + 2, left_w + 2, selected.title, self.theme.attrs.heading)
        safe_addstr(self.stdscr, y + 4, left_w + 2, selected.summary, self.theme.attrs.info)
        safe_addstr(self.stdscr, y + 6, left_w + 2, "Prerequisites:", self.theme.attrs.heading)
        safe_addstr(self.stdscr, y + 7, left_w + 2, selected.prerequisites, self.theme.attrs.panel)
        safe_addstr(self.stdscr, y + 9, left_w + 2, "Flow is button-driven: no y/n prompts in this UI.", self.theme.attrs.muted)

        btn_y = y + h - 3
        for idx, (label, action, primary, danger) in enumerate(
            [
                ("Configure", "home:btn:configure", False, False),
                ("Run", "home:btn:run", True, selected.danger),
                ("Quit", "home:btn:quit", False, False),
            ]
        ):
            fid = action
            items.append(fid)
            focused = self.focus.current == fid
            rect = draw_button(
                self.stdscr,
                self.theme,
                btn_y,
                2 + idx * 16,
                label,
                focused=focused,
                primary=primary,
                danger=danger,
                action=action,
            )
            self.mouse_targets.append(rect)

        preferred = self.focus.current if self.focus.current in items else f"home:op:{self.selected_operation}"
        self.focus.set_items(items, preferred=preferred)

    def _draw_editor(self, y: int, h: int, w: int) -> None:
        if self.editor is None:
            return
        install_mode = self.editor.operation == "install"
        spec: Any = self.install_spec if install_mode else self.uninstall_spec
        steps: tuple[WizardStep, ...] = INSTALL_STEPS if install_mode else UNINSTALL_STEPS
        fields_index: dict[str, FieldDef] = FIELD_INDEX_INSTALL if install_mode else FIELD_INDEX_UNINSTALL
        all_fields: tuple[FieldDef, ...] = INSTALL_FIELDS if install_mode else UNINSTALL_FIELDS

        draw_box(self.stdscr, y, 0, h, w, f" {'INSTALL' if install_mode else 'UNINSTALL'} :: SPEC EDITOR ", self.theme.attrs.panel)
        tab_y = y + 1
        col = 2
        items: list[str] = []
        for idx, step in enumerate(steps):
            fid = f"editor:tab:{idx}"
            items.append(fid)
            focused = self.focus.current == fid
            rect = draw_button(
                self.stdscr,
                self.theme,
                tab_y,
                col,
                step.title,
                focused=focused,
                primary=idx == self.editor.step_idx,
                action=fid,
            )
            self.mouse_targets.append(rect)
            col += rect.w + 1

        content_y = y + 3
        content_h = h - 8
        draw_box(self.stdscr, content_y, 1, content_h, w - 2, f" STEP :: {steps[self.editor.step_idx].title} ", self.theme.attrs.panel)

        step = steps[self.editor.step_idx]
        if step.key == "review":
            review_lines = build_review_lines(spec, all_fields)
            for idx, line in enumerate(review_lines[: max(0, content_h - 3)]):
                safe_addstr(self.stdscr, content_y + 1 + idx, 3, line, self.theme.attrs.panel)
            if install_mode:
                errors = self.install_spec.validate()
                if errors:
                    safe_addstr(self.stdscr, content_y + content_h - 2, 3, f"Validation: {errors[0]}", self.theme.attrs.error)
                else:
                    safe_addstr(self.stdscr, content_y + content_h - 2, 3, "Validation: OK", self.theme.attrs.success)
        else:
            row = content_y + 1
            fields = [fields_index[name] for name in step.fields if name in fields_index]
            self.editor.row_idx = clamp(self.editor.row_idx, 0, max(0, len(fields) - 1))
            for idx, field in enumerate(fields):
                fid = f"editor:field:{field.name}"
                items.append(fid)
                focused = self.focus.current == fid
                label_attr = self.theme.attrs.focus if focused else self.theme.attrs.heading
                safe_addstr(self.stdscr, row, 3, f"{field.label}", label_attr)
                value = getattr(spec, field.name)
                if field.ftype == "bool":
                    rect = draw_toggle(
                        self.stdscr,
                        self.theme,
                        row,
                        40,
                        bool(value),
                        focused=focused,
                        action=fid,
                    )
                    self.mouse_targets.append(rect)
                elif field.ftype == "choice":
                    options = list(field.options)
                    selected_idx = options.index(str(value)) if str(value) in options else 0
                    focus_idx = selected_idx if focused else -1
                    rects = draw_segmented(
                        self.stdscr,
                        self.theme,
                        row,
                        40,
                        options,
                        selected_idx,
                        focus_idx,
                        f"editor:choice:{field.name}",
                    )
                    self.mouse_targets.extend(rects)
                else:
                    shown = str(value) or "(empty)"
                    shown = shown[: max(8, w - 58)]
                    safe_addstr(self.stdscr, row, 40, shown, self.theme.attrs.panel)
                    rect = draw_button(
                        self.stdscr,
                        self.theme,
                        row,
                        max(42, w - 14),
                        "Edit",
                        focused=focused,
                        action=fid,
                    )
                    self.mouse_targets.append(rect)
                if field.help_text:
                    safe_addstr(self.stdscr, row + 1, 5, field.help_text[: max(0, w - 12)], self.theme.attrs.muted)
                    row += 1
                row += 1

        btn_y = y + h - 3
        btns = [
            ("Back", "editor:btn:back", False, False),
            ("Next", "editor:btn:next", False, False),
            ("Run", "editor:btn:run", True, not install_mode),
        ]
        if self.editor.step_idx >= len(steps) - 1:
            btns[1] = ("Prev", "editor:btn:prev", False, False)
        for idx, (label, action, primary, danger) in enumerate(btns):
            fid = action
            items.append(fid)
            rect = draw_button(
                self.stdscr,
                self.theme,
                btn_y,
                3 + idx * 16,
                label,
                focused=self.focus.current == fid,
                primary=primary,
                danger=danger,
                action=action,
            )
            self.mouse_targets.append(rect)

        if install_mode:
            errors = self.install_spec.validate()
            if errors:
                safe_addstr(self.stdscr, btn_y, 52, f"Install blocked: {errors[0]}", self.theme.attrs.error)
            else:
                safe_addstr(self.stdscr, btn_y, 52, "Install spec valid.", self.theme.attrs.success)

        preferred = f"editor:tab:{self.editor.step_idx}" if self.focus.current == "" else None
        self.focus.set_items(items, preferred=preferred)

    def _draw_run_dashboard(self, y: int, h: int, w: int) -> None:
        run = self.run_state
        if run is None:
            draw_box(self.stdscr, y, 0, h, w, " RUN ")
            safe_addstr(self.stdscr, y + 2, 2, "No active run.")
            return

        left_w = max(38, int(w * 0.40))
        right_w = w - left_w
        top_h = max(11, int(h * 0.42))
        bottom_h = h - top_h

        draw_box(self.stdscr, y, 0, top_h, left_w, " STAGE TIMELINE ", self.theme.attrs.panel)
        draw_box(self.stdscr, y, left_w, top_h, right_w, " RUN CONTEXT ", self.theme.attrs.panel)
        draw_box(self.stdscr, y + top_h, 0, bottom_h, w, " LIVE LOG ", self.theme.attrs.panel)

        row = y + 1
        viewport = top_h - 2
        for stage_id in run.stage_order[:viewport]:
            stage = run.stages[stage_id]
            icon, kind = STAGE_META.get(stage_id, ("[ ]", "info"))
            if stage.status == "ok":
                status_text = "[+]"
                attr = self.theme.attrs.success
            elif stage.status == "failed":
                status_text = "[!]"
                attr = self.theme.attrs.error
            elif stage.status == "running":
                status_text = f"[{spinner(self.ui.spinner_tick)}]"
                attr = self.theme.attrs.primary
            elif stage.status == "skipped":
                status_text = "[-]"
                attr = self.theme.attrs.muted
            else:
                status_text = "[ ]"
                attr = self.theme.attrs.muted
            safe_addstr(self.stdscr, row, 2, f"{icon} {status_text} {stage.title}", attr)
            row += 1

        overall = run.overall_progress
        draw_meter(self.stdscr, self.theme, y + 1, left_w + 2, right_w - 4, overall, "Overall")
        active = run.stages.get(run.active_stage_id, None) if run.active_stage_id else None
        stage_ratio = 0.0
        if active and active.total > 0:
            stage_ratio = min(1.0, max(0.0, active.current / active.total))
        draw_meter(self.stdscr, self.theme, y + 2, left_w + 2, right_w - 4, stage_ratio, "Stage  ")
        safe_addstr(self.stdscr, y + 4, left_w + 2, f"Run ID: {run.run_id}", self.theme.attrs.panel)
        safe_addstr(self.stdscr, y + 5, left_w + 2, f"Status: {run.status}", self.theme.attrs.heading)
        safe_addstr(self.stdscr, y + 6, left_w + 2, f"Active stage: {run.active_stage_id or '-'}", self.theme.attrs.info)
        if active:
            safe_addstr(self.stdscr, y + 7, left_w + 2, f"Message: {active.message or '(working)'}", self.theme.attrs.muted)
            if active.rate_hint:
                safe_addstr(self.stdscr, y + 8, left_w + 2, f"Rate: {active.rate_hint}", self.theme.attrs.muted)
            if active.eta_hint:
                safe_addstr(self.stdscr, y + 9, left_w + 2, f"ETA: {active.eta_hint}", self.theme.attrs.muted)
        if run.status == "failed" and self.last_result:
            self._draw_failure_inspector(y + 10, left_w + 2, right_w - 4)

        items: list[str] = []
        log_header_y = y + top_h + 1
        safe_addstr(self.stdscr, log_header_y, 2, "Levels:", self.theme.attrs.heading)
        x = 10
        for level in self.log_level_order:
            fid = f"run:level:{level}"
            items.append(fid)
            enabled = level in self.ui.log_level_mask
            rect = draw_toggle(self.stdscr, self.theme, log_header_y, x, enabled, focused=self.focus.current == fid, action=fid)
            self.mouse_targets.append(rect)
            safe_addstr(self.stdscr, log_header_y, x + 2, level.upper(), self.theme.attrs.panel)
            x += rect.w + 1

        safe_addstr(self.stdscr, log_header_y + 1, 2, "Categories:", self.theme.attrs.heading)
        x = 14
        for cat in ["system", "network", "proxy", "service", "auth"]:
            fid = f"run:cat:{cat}"
            items.append(fid)
            enabled = cat in self.log_category_mask
            rect = draw_toggle(self.stdscr, self.theme, log_header_y + 1, x, enabled, focused=self.focus.current == fid, action=fid)
            self.mouse_targets.append(rect)
            safe_addstr(self.stdscr, log_header_y + 1, x + 2, cat, self.theme.attrs.panel)
            x += rect.w + 1

        filtered = self.logstore.filtered(self.ui.log_level_mask, self.ui.log_search, self.log_category_mask)
        viewport = bottom_h - 6
        max_scroll = max(0, len(filtered) - viewport)
        self.ui.run_scroll = clamp(self.ui.run_scroll, 0, max_scroll)
        start = max(0, len(filtered) - viewport - self.ui.run_scroll)
        slice_entries = filtered[start : start + viewport]
        for idx, entry in enumerate(slice_entries):
            attr = self.theme.attrs.panel
            if entry.level == "warn":
                attr = self.theme.attrs.warning
            elif entry.level == "error":
                attr = self.theme.attrs.error
            elif entry.level == "debug":
                attr = self.theme.attrs.muted
            safe_addstr(self.stdscr, log_header_y + 2 + idx, 2, entry.format_line(), attr)

        btn_row = y + h - 3
        for idx, (label, action, primary) in enumerate(
            [
                ("Retry", "run:btn:retry", False),
                ("Diagnose", "run:btn:diagnose", False),
                ("Export", "run:btn:export", False),
                ("Back", "run:btn:back", False),
            ]
        ):
            fid = action
            items.append(fid)
            disabled = bool(self.run_thread and self.run_thread.is_alive() and action in {"run:btn:retry", "run:btn:back"})
            rect = draw_button(
                self.stdscr,
                self.theme,
                btn_row,
                2 + idx * 15,
                label,
                focused=self.focus.current == fid,
                primary=primary,
                disabled=disabled,
                action=action,
            )
            self.mouse_targets.append(rect)

        if self.ui.log_search:
            safe_addstr(self.stdscr, btn_row, 64, f"Search: {self.ui.log_search}", self.theme.attrs.muted)
        self.focus.set_items(items, preferred=self.focus.current or "run:btn:retry")

    def _draw_failure_inspector(self, y: int, x: int, w: int) -> None:
        if not self.last_result or not self.last_result.errors:
            return
        primary = self.last_result.errors[0]
        safe_addstr(self.stdscr, y, x, f"Failure: {primary.code}", self.theme.attrs.error)
        safe_addstr(self.stdscr, y + 1, x, primary.message[:w], self.theme.attrs.error)
        if primary.suggested_fix:
            safe_addstr(self.stdscr, y + 2, x, f"Fix: {primary.suggested_fix}"[:w], self.theme.attrs.muted)
        for idx, action in enumerate(self.last_result.next_actions[:2]):
            safe_addstr(self.stdscr, y + 3 + idx, x, f"- {action}"[:w], self.theme.attrs.muted)

    def _draw_status(self, y: int, h: int, w: int) -> None:
        draw_box(self.stdscr, y, 0, h, w, " STATUS ", self.theme.attrs.panel)
        service = detect_service_state()
        safe_addstr(self.stdscr, y + 2, 2, f"mailclient service: {service}", self.theme.attrs.heading)
        safe_addstr(self.stdscr, y + 4, 2, f"Host: {detect_host()}", self.theme.attrs.panel)
        safe_addstr(self.stdscr, y + 5, 2, f"Arch: {detect_arch()}", self.theme.attrs.panel)
        safe_addstr(self.stdscr, y + 7, 2, f"Runner logs: {self.logstore.log_path}", self.theme.attrs.muted)
        safe_addstr(self.stdscr, y + 8, 2, "Use Diagnose for full network/proxy checks.", self.theme.attrs.muted)
        items = ["status:btn:diagnose", "status:btn:back"]
        r1 = draw_button(
            self.stdscr,
            self.theme,
            y + h - 3,
            2,
            "Diagnose",
            focused=self.focus.current == "status:btn:diagnose",
            action="status:btn:diagnose",
        )
        r2 = draw_button(
            self.stdscr,
            self.theme,
            y + h - 3,
            18,
            "Back",
            focused=self.focus.current == "status:btn:back",
            action="status:btn:back",
        )
        self.mouse_targets.extend([r1, r2])
        self.focus.set_items(items, preferred=self.focus.current or "status:btn:diagnose")

    def _handle_key(self, key: object) -> None:
        if key == curses.KEY_MOUSE:
            self._handle_mouse()
            return
        if key in ("\t",):
            self.focus.next()
            return
        if key == curses.KEY_BTAB:
            self.focus.prev()
            return
        if key in ("q", "Q") and self.mode == "home":
            self.running = False
            return
        if key == curses.KEY_F5 and self.mode in {"run", "install_editor", "uninstall_editor"}:
            self._rerun_current_operation()
            return
        if key == curses.KEY_F9:
            self._start_run("diagnose")
            return
        if key in ("/",) and self.mode == "run":
            query = self._prompt_line("Log search", self.ui.log_search)
            if query is not None:
                self.ui.log_search = query
                self.ui.status_line = f"Log search set: {query or '(none)'}"
            return
        if key == curses.KEY_NPAGE and self.mode == "run":
            self.ui.run_scroll = max(0, self.ui.run_scroll - 10)
            return
        if key == curses.KEY_PPAGE and self.mode == "run":
            self.ui.run_scroll += 10
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
        if is_enter(key) or key == " ":
            self._activate_focus(self.focus.current)

    def _handle_escape(self) -> None:
        if self.mode in {"install_editor", "uninstall_editor", "status"}:
            self.mode = "home"
            self.editor = None
            self.ui.status_line = "Back to home."
            return
        if self.mode == "run":
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run is active. Cancel first."
                return
            self.mode = "home"
            self.ui.status_line = "Back to home."

    def _handle_vertical(self, delta: int) -> None:
        cur = self.focus.current
        if self.mode == "home":
            if cur.startswith("home:op:"):
                idx = clamp(int(cur.rsplit(":", 1)[1]) + delta, 0, len(self.cards) - 1)
                self.selected_operation = idx
                self.focus.set_items(self.focus.items, preferred=f"home:op:{idx}")
            return
        if self.mode in {"install_editor", "uninstall_editor"} and self.editor is not None:
            step = self._current_step()
            if step and step.fields:
                self.editor.row_idx = clamp(self.editor.row_idx + delta, 0, len(step.fields) - 1)
                field_name = step.fields[self.editor.row_idx]
                self.focus.set_items(self.focus.items, preferred=f"editor:field:{field_name}")

    def _handle_horizontal(self, delta: int) -> None:
        cur = self.focus.current
        if cur.startswith("editor:tab:") and self.editor is not None:
            steps = self._editor_steps()
            idx = clamp(int(cur.rsplit(":", 1)[1]) + delta, 0, len(steps) - 1)
            self.editor.step_idx = idx
            self.editor.row_idx = 0
            return
        if cur.startswith("editor:choice:"):
            parts = cur.split(":")
            if len(parts) < 4:
                return
            field_name = parts[2]
            choice_idx = int(parts[3]) + delta
            self._set_choice(field_name, choice_idx)

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
        if focus_id.startswith("home:"):
            self._activate_home(focus_id)
            return
        if focus_id.startswith("editor:"):
            self._activate_editor(focus_id)
            return
        if focus_id.startswith("run:"):
            self._activate_run(focus_id)
            return
        if focus_id.startswith("status:"):
            self._activate_status(focus_id)

    def _activate_home(self, focus_id: str) -> None:
        if focus_id.startswith("home:op:"):
            self.selected_operation = clamp(int(focus_id.rsplit(":", 1)[1]), 0, len(self.cards) - 1)
            self._open_selected_configure()
            return
        if focus_id == "home:btn:quit":
            self.running = False
            return
        if focus_id == "home:btn:configure":
            self._open_selected_configure()
            return
        selected = self.cards[self.selected_operation]
        if focus_id == "home:btn:run":
            if selected.key == "status":
                self.mode = "status"
                return
            if selected.key == "install":
                self._start_run("install")
            elif selected.key == "uninstall":
                if not self._confirm_dialog(
                    ConfirmModal(
                        title="Proceed with uninstall?",
                        detail="This action may remove app files and data according to your toggles.",
                        cancel_label="Cancel",
                        confirm_label="Run",
                    )
                ):
                    self.ui.status_line = "Uninstall cancelled."
                    return
                self._start_run("uninstall")
            else:
                self._start_run("diagnose")

    def _open_selected_configure(self) -> None:
        selected = self.cards[self.selected_operation]
        if selected.key == "install":
            self.mode = "install_editor"
            self.editor = EditorState(operation="install")
        elif selected.key == "uninstall":
            self.mode = "uninstall_editor"
            self.editor = EditorState(operation="uninstall")
        elif selected.key == "status":
            self.mode = "status"
        else:
            self._start_run("diagnose")
        self.ui.status_line = f"Configured action: {selected.title}"

    def _activate_editor(self, focus_id: str) -> None:
        if self.editor is None:
            return
        if focus_id.startswith("editor:tab:"):
            self.editor.step_idx = clamp(int(focus_id.rsplit(":", 1)[1]), 0, len(self._editor_steps()) - 1)
            self.editor.row_idx = 0
            return
        if focus_id == "editor:btn:back":
            self.mode = "home"
            self.editor = None
            self.ui.status_line = "Back to home."
            return
        if focus_id == "editor:btn:next":
            self.editor.step_idx = clamp(self.editor.step_idx + 1, 0, len(self._editor_steps()) - 1)
            self.editor.row_idx = 0
            return
        if focus_id == "editor:btn:prev":
            self.editor.step_idx = clamp(self.editor.step_idx - 1, 0, len(self._editor_steps()) - 1)
            self.editor.row_idx = 0
            return
        if focus_id == "editor:btn:run":
            if self.editor.operation == "install":
                errors = self.install_spec.validate()
                if errors:
                    self.ui.status_line = f"Cannot run install: {errors[0]}"
                    return
            self._start_run(self.editor.operation)
            return
        if focus_id.startswith("editor:choice:"):
            parts = focus_id.split(":")
            if len(parts) < 4:
                return
            self._set_choice(parts[2], int(parts[3]))
            return
        if focus_id.startswith("editor:field:"):
            field_name = focus_id.split(":", 2)[2]
            field = self._field_def(field_name)
            if field is None:
                return
            self._edit_field(field)

    def _activate_run(self, focus_id: str) -> None:
        if focus_id.startswith("run:level:"):
            level = focus_id.split(":")[-1]
            if level in self.ui.log_level_mask:
                self.ui.log_level_mask.remove(level)
            else:
                self.ui.log_level_mask.add(level)
            if not self.ui.log_level_mask:
                self.ui.log_level_mask.add("error")
            return
        if focus_id.startswith("run:cat:"):
            cat = focus_id.split(":")[-1]
            if cat in self.log_category_mask:
                self.log_category_mask.remove(cat)
            else:
                self.log_category_mask.add(cat)
            if not self.log_category_mask:
                self.log_category_mask.add("system")
            return
        if focus_id == "run:btn:retry":
            self._rerun_current_operation()
            return
        if focus_id == "run:btn:diagnose":
            self._start_run("diagnose")
            return
        if focus_id == "run:btn:export":
            if self.last_result:
                payload = self.last_summary_payload or self._build_summary_payload(self.active_operation, self.last_result)
                path = self.logstore.export_summary(payload)
                self.ui.status_line = f"Summary exported: {path}"
            else:
                self.ui.status_line = "No result to export yet."
            return
        if focus_id == "run:btn:back":
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run in progress. Cancel first."
                return
            self.mode = "home"
            self.ui.status_line = "Back to home."

    def _activate_status(self, focus_id: str) -> None:
        if focus_id == "status:btn:back":
            self.mode = "home"
            self.ui.status_line = "Back to home."
        elif focus_id == "status:btn:diagnose":
            self._start_run("diagnose")

    def _editor_steps(self) -> tuple[WizardStep, ...]:
        if self.editor and self.editor.operation == "install":
            return INSTALL_STEPS
        return UNINSTALL_STEPS

    def _current_step(self) -> WizardStep | None:
        if self.editor is None:
            return None
        steps = self._editor_steps()
        if not steps:
            return None
        idx = clamp(self.editor.step_idx, 0, len(steps) - 1)
        self.editor.step_idx = idx
        return steps[idx]

    def _field_def(self, field_name: str) -> FieldDef | None:
        if self.editor and self.editor.operation == "install":
            return FIELD_INDEX_INSTALL.get(field_name)
        return FIELD_INDEX_UNINSTALL.get(field_name)

    def _editor_obj(self) -> Any:
        if self.editor and self.editor.operation == "install":
            return self.install_spec
        return self.uninstall_spec

    def _set_choice(self, field_name: str, idx: int) -> None:
        field = self._field_def(field_name)
        if field is None or field.ftype != "choice":
            return
        opts = list(field.options)
        if not opts:
            return
        idx = clamp(idx, 0, len(opts) - 1)
        setattr(self._editor_obj(), field_name, opts[idx])
        self.ui.status_line = f"{field.label} set to {opts[idx]}"

    def _edit_field(self, field: FieldDef) -> None:
        obj = self._editor_obj()
        current = getattr(obj, field.name)
        if field.ftype == "bool":
            next_value = not bool(current)
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
            self.ui.status_line = f"{field.label} set to {'Enabled' if next_value else 'Disabled'}"
            return
        if field.ftype == "choice":
            selected = self._select_choice(field.label, list(field.options), str(current))
            if selected is None:
                self.ui.status_line = f"{field.label} unchanged."
                return
            setattr(obj, field.name, selected)
            self.ui.status_line = f"{field.label} set to {selected}"
            return
        value = self._prompt_line(field.label, str(current))
        if value is None:
            self.ui.status_line = f"{field.label} unchanged."
            return
        setattr(obj, field.name, value)
        self.ui.status_line = f"{field.label} updated."

    def _prompt_line(self, label: str, initial: str) -> str | None:
        h, w = self.stdscr.getmaxyx()
        win_h = 6
        win_w = max(60, int(w * 0.75))
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        buf = list(initial)
        cur = len(buf)
        self.stdscr.timeout(-1)
        curses.curs_set(1)
        try:
            while True:
                draw_box(self.stdscr, y, x, win_h, win_w, f" EDIT :: {label} ", self.theme.attrs.panel)
                safe_addstr(self.stdscr, y + 1, x + 2, "Enter=Save  Esc=Cancel  Ctrl+U=Clear", self.theme.attrs.muted)
                max_len = win_w - 4
                text = "".join(buf)
                if len(text) <= max_len:
                    display = text
                    offset = 0
                else:
                    offset = max(0, cur - max_len)
                    display = text[offset : offset + max_len]
                safe_addstr(self.stdscr, y + 3, x + 2, " " * max_len)
                safe_addstr(self.stdscr, y + 3, x + 2, display, self.theme.attrs.panel)
                cursor_col = x + 2 + max(0, min(max_len - 1, cur - offset))
                self.stdscr.move(y + 3, cursor_col)
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if is_enter(key):
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
                if is_backspace(key) or key in ("\x7f", "\b"):
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
                draw_box(self.stdscr, y, x, win_h, win_w, f" SELECT :: {label} ", self.theme.attrs.panel)
                viewport = win_h - 4
                if idx < top:
                    top = idx
                if idx >= top + viewport:
                    top = idx - viewport + 1
                for row in range(viewport):
                    opt_i = top + row
                    ly = y + 2 + row
                    safe_addstr(self.stdscr, ly, x + 2, " " * (win_w - 4))
                    if opt_i >= len(options):
                        continue
                    opt = options[opt_i]
                    attr = self.theme.attrs.focus if opt_i == idx else self.theme.attrs.panel
                    safe_addstr(self.stdscr, ly, x + 2, opt[: win_w - 5], attr)
                safe_addstr(self.stdscr, y + win_h - 2, x + 2, "Arrows move | Enter select | Esc cancel", self.theme.attrs.muted)
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
                if is_enter(key):
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
                draw_box(self.stdscr, y, x, win_h, win_w, " CONFIRM ", self.theme.attrs.panel)
                safe_addstr(self.stdscr, y + 1, x + 2, modal.title[: win_w - 4], self.theme.attrs.heading)
                safe_addstr(self.stdscr, y + 3, x + 2, modal.detail[: win_w - 4], self.theme.attrs.panel)
                r_cancel = draw_button(
                    self.stdscr,
                    self.theme,
                    y + 6,
                    x + 2,
                    modal.cancel_label,
                    focused=selected == 0,
                    action="modal:cancel",
                )
                r_confirm = draw_button(
                    self.stdscr,
                    self.theme,
                    y + 6,
                    x + 18,
                    modal.confirm_label,
                    focused=selected == 1,
                    primary=True,
                    action="modal:confirm",
                )
                safe_addstr(self.stdscr, y + 7, x + 2, "Left/Right select | Enter confirm | Esc cancel", self.theme.attrs.muted)
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
                if is_enter(key):
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
        self.mode = "run"
        self.ui.run_scroll = 0
        self.ui.status_line = f"Running {operation}..."

        if operation == "install":
            preflight_error = self._check_install_preflight()
            if preflight_error is not None:
                apply_runner_event(self.run_state, {"type": "run_start", "run_id": run_id, "operation": operation})
                apply_runner_event(
                    self.run_state,
                    {"type": "stage_start", "stage_id": "preflight", "title": "Preflight", "weight": "10", "message": "started"},
                )
                apply_runner_event(
                    self.run_state,
                    {"type": "stage_result", "stage_id": "preflight", "status": "failed", "error_code": "E_PREFLIGHT"},
                )
                apply_runner_event(
                    self.run_state,
                    {"type": "run_result", "status": "failed", "failed_stage": "preflight", "exit_code": "1"},
                )
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
                if status == "ok":
                    self.ui.status_line = "Run completed successfully."
                elif status == "cancelled":
                    self.ui.status_line = "Run cancelled."
                else:
                    self.ui.status_line = f"Run failed in stage {self.run_state.failed_stage or 'unknown'}."

    def _rerun_current_operation(self) -> None:
        if self.run_thread and self.run_thread.is_alive():
            self.ui.status_line = "Run already in progress."
            return
        if self.mode in {"install_editor", "home"}:
            selected = self.cards[self.selected_operation].key if self.mode == "home" else (self.editor.operation if self.editor else "install")
            if selected in {"install", "uninstall", "diagnose"}:
                self._start_run(selected)
            return
        if self.active_operation:
            self._start_run(self.active_operation)

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
        try:
            probe = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except Exception as exc:
            return RunnerError(
                code="E_PREFLIGHT",
                message=f"Failed privilege preflight: {exc}",
                stage_id="preflight",
                suggested_fix="Run as root or refresh sudo credentials.",
            )
        if probe.returncode == 0:
            return None
        return RunnerError(
            code="E_PREFLIGHT",
            message="Install requires root privileges. sudo -n failed (no cached credentials).",
            stage_id="preflight",
            suggested_fix="Run 'sudo -v' first, or launch despatch.py as root.",
        )

    @staticmethod
    def _command_exists(name: str) -> bool:
        return any(
            os.access(Path(path) / name, os.X_OK)
            for path in os.environ.get("PATH", "").split(os.pathsep)
            if path
        )

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


def _main(stdscr: curses.window) -> None:
    app = DespatchTUI(stdscr)
    app.run()


def _run_with_event_stream(runner: OperationRunner, op: str, spec: Any, logstore: LogStore) -> int:
    stage_defs = INSTALL_STAGE_DEFS if op == "install" else UNINSTALL_STAGE_DEFS if op == "uninstall" else DIAG_STAGE_DEFS
    run_state = new_run_state(op, f"plain-{int(time.time())}", stage_defs)
    cancel = CancelToken()

    def on_event(evt: dict[str, Any]) -> None:
        apply_runner_event(run_state, evt)
        etype = evt.get("type", "")
        if etype == "stage_start" and evt.get("message") != "pending":
            title = evt.get("title", evt.get("stage_id", "stage"))
            print(f"\n==> {title}")
        elif etype == "log":
            level = str(evt.get("level", "info")).upper()
            category = str(evt.get("category", "system"))
            print(f"[{level:<5}] [{category}] {evt.get('message', '')}")
        elif etype == "run_result":
            print(f"\nRun result: {evt.get('status')} (exit_code={evt.get('exit_code')})")

    if op == "install":
        result = runner.run_install(spec, logstore, cancel, on_event)
    elif op == "uninstall":
        result = runner.run_uninstall(spec, logstore, cancel, on_event)
    else:
        result = runner.run_diagnose(spec, logstore, cancel, on_event)
    print(f"Log file: {logstore.log_path}")
    return 0 if result.status == "ok" else 1


def _plain_choose(title: str, options: list[str]) -> int:
    while True:
        print(f"\n{title}")
        for idx, opt in enumerate(options, start=1):
            print(f"{idx}) {opt}")
        raw = input("Select number: ").strip()
        if raw.isdigit():
            val = int(raw)
            if 1 <= val <= len(options):
                return val - 1
        print("Invalid selection.")


def _plain_edit_value(label: str, current: str) -> str:
    raw = input(f"{label} [{current}] (blank keep): ").strip()
    return current if raw == "" else raw


def _plain_edit_install(spec: InstallSpec) -> bool:
    field_defs = list(INSTALL_FIELDS)
    while True:
        print("\n=== Install Spec Editor ===")
        for idx, field in enumerate(field_defs, start=1):
            value = getattr(spec, field.name)
            shown = "Enabled" if isinstance(value, bool) and value else "Disabled" if isinstance(value, bool) else (str(value) or "(empty)")
            print(f"{idx:2d}) {field.label:<35} {shown}")
        print("R) Run install   B) Back")
        cmd = input("Action: ").strip().lower()
        if cmd == "r":
            errs = spec.validate()
            if errs:
                print(f"Validation error: {errs[0]}")
                continue
            return True
        if cmd == "b":
            return False
        if not cmd.isdigit():
            print("Use field number, R, or B.")
            continue
        idx = int(cmd) - 1
        if idx < 0 or idx >= len(field_defs):
            print("Invalid field number.")
            continue
        field = field_defs[idx]
        cur = getattr(spec, field.name)
        if field.ftype == "bool":
            setattr(spec, field.name, not bool(cur))
            continue
        if field.ftype == "choice":
            choice_idx = _plain_choose(field.label, list(field.options))
            setattr(spec, field.name, list(field.options)[choice_idx])
            continue
        setattr(spec, field.name, _plain_edit_value(field.label, str(cur)))


def _plain_edit_uninstall(spec: UninstallSpec) -> bool:
    field_defs = list(UNINSTALL_FIELDS)
    while True:
        print("\n=== Uninstall Spec Editor ===")
        for idx, field in enumerate(field_defs, start=1):
            value = getattr(spec, field.name)
            shown = "Enabled" if bool(value) else "Disabled"
            print(f"{idx:2d}) {field.label:<35} {shown}")
        print("R) Run uninstall   B) Back")
        cmd = input("Action: ").strip().lower()
        if cmd == "r":
            return True
        if cmd == "b":
            return False
        if not cmd.isdigit():
            print("Use field number, R, or B.")
            continue
        idx = int(cmd) - 1
        if idx < 0 or idx >= len(field_defs):
            print("Invalid field number.")
            continue
        field = field_defs[idx]
        cur = getattr(spec, field.name)
        setattr(spec, field.name, not bool(cur))


def run_plain_console() -> int:
    paths = detect_paths()
    runner = OperationRunner(paths)
    logstore = LogStore(max_entries=8000)
    hostname = socket.gethostname()
    default_domain = hostname if "." in hostname else "example.com"
    proxies = detect_proxy_candidates()
    install_spec = InstallSpec(
        base_domain=default_domain,
        proxy_server=proxies[0] if proxies else "nginx",
        proxy_server_name=default_domain,
    )
    uninstall_spec = UninstallSpec()

    while True:
        print("\nDespatch Plain Console")
        print("======================")
        print("1) Install / Upgrade")
        print("2) Uninstall")
        print("3) Diagnose Access")
        print("4) Quit")
        choice = input("Select [1-4]: ").strip()
        if choice == "1":
            if _plain_edit_install(install_spec):
                return _run_with_event_stream(runner, "install", install_spec, logstore)
            continue
        if choice == "2":
            if _plain_edit_uninstall(uninstall_spec):
                return _run_with_event_stream(runner, "uninstall", uninstall_spec, logstore)
            continue
        if choice == "3":
            return _run_with_event_stream(runner, "diagnose", DiagnoseSpec(), logstore)
        if choice == "4":
            return 0
        print("Unknown option.")


def _prompt_text(label: str, default: str) -> str:
    raw = input(f"{label} [{default}]: ").strip()
    return raw or default


def _prompt_bool(label: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{label} ({hint}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


def run_plain_console_legacy() -> int:
    paths = detect_paths()
    runner = OperationRunner(paths)
    logstore = LogStore(max_entries=8000)
    print("Despatch Legacy Prompt Mode")
    print("===========================")
    print("1) Install / Upgrade")
    print("2) Uninstall")
    print("3) Diagnose Access")
    print("4) Quit")
    choice = input("Select [1-4]: ").strip()
    if choice == "4":
        return 0
    if choice == "1":
        hostname = socket.gethostname()
        default_domain = hostname if "." in hostname else "example.com"
        spec = InstallSpec(
            base_domain=_prompt_text("Base domain", default_domain),
            listen_addr=_prompt_text("Listen address", ":8080"),
            install_service=_prompt_bool("Install systemd service", True),
            proxy_setup=_prompt_bool("Configure reverse proxy", True),
            proxy_server=_prompt_text("Proxy server", "nginx"),
            proxy_server_name=_prompt_text("Proxy server name", default_domain),
            proxy_tls=_prompt_bool("Enable proxy TLS", False),
            dovecot_auth_mode=_prompt_text("Dovecot auth mode (pam/sql)", "pam"),
            run_diagnose=_prompt_bool("Run diagnose at end", True),
        )
        if spec.proxy_tls:
            spec.proxy_cert = _prompt_text("TLS cert path", f"/etc/letsencrypt/live/{spec.proxy_server_name}/fullchain.pem")
            spec.proxy_key = _prompt_text("TLS key path", f"/etc/letsencrypt/live/{spec.proxy_server_name}/privkey.pem")
        if spec.dovecot_auth_mode == "sql":
            spec.dovecot_auth_db_driver = _prompt_text("Dovecot SQL driver", "mysql")
            spec.dovecot_auth_db_dsn = _prompt_text("Dovecot SQL DSN", "")
        errors = spec.validate()
        if errors:
            print(f"Validation failed: {errors[0]}")
            return 1
        return _run_with_event_stream(runner, "install", spec, logstore)
    if choice == "2":
        spec = UninstallSpec(
            backup_env=_prompt_bool("Backup /opt/mailclient/.env", True),
            backup_data=_prompt_bool("Backup /var/lib/mailclient", True),
            remove_app_files=_prompt_bool("Remove /opt/mailclient", True),
            remove_app_data=_prompt_bool("Remove /var/lib/mailclient", True),
            remove_system_user=_prompt_bool("Remove mailclient system user", True),
            remove_nginx_site=_prompt_bool("Remove nginx site", True),
            remove_apache_site=_prompt_bool("Remove apache2 site", True),
            remove_checkout=_prompt_bool("Remove /opt/mailclient-installer", False),
        )
        return _run_with_event_stream(runner, "uninstall", spec, logstore)
    if choice == "3":
        return _run_with_event_stream(runner, "diagnose", DiagnoseSpec(), logstore)
    return 1


if __name__ == "__main__":
    if "--legacy-prompts" in sys.argv:
        raise SystemExit(run_plain_console_legacy())
    if "--plain" in sys.argv:
        raise SystemExit(run_plain_console())
    try:
        curses.wrapper(_main)
    except KeyboardInterrupt:
        pass
