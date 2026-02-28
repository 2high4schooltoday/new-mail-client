#!/usr/bin/env python3
"""Despatch TUI: state-driven installer/uninstaller dashboard (stdlib only)."""

from __future__ import annotations

import curses
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

from tui.keys import is_backspace, is_enter
from tui.logstore import LogStore
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
from tui.state import UIState, apply_runner_event, new_run_state
from tui.system_ops import CancelToken, detect_arch, detect_host, detect_paths, detect_proxy_candidates, detect_service_state
from tui.views import clamp, draw_box, progress_bar, safe_addstr, spinner


@dataclass
class OperationItem:
    key: str
    title: str
    summary: str
    danger: bool = False


class DespatchTUI:
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr = stdscr
        self.ui = UIState()
        self.paths = detect_paths()
        self.runner = OperationRunner(self.paths)
        self.logstore = LogStore(max_entries=8000)
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.run_thread: threading.Thread | None = None
        self.cancel_token: CancelToken | None = None
        self.run_state: RunState | None = None
        self.last_result: OperationResult | None = None
        self.last_summary_payload: dict[str, Any] = {}
        self.active_operation: str = ""
        self.search_query = ""

        hostname = detect_host()
        default_domain = hostname if "." in hostname else "example.com"
        proxies = detect_proxy_candidates()
        self.install_spec = InstallSpec(
            base_domain=default_domain,
            proxy_server=proxies[0] if proxies else "nginx",
            proxy_server_name=default_domain,
        )
        self.uninstall_spec = UninstallSpec()

        self.operations = [
            OperationItem("install", "Install / Upgrade Despatch", "Full install with non-interactive staged execution."),
            OperationItem("uninstall", "Uninstall Despatch", "Safe removal with optional backups.", danger=True),
            OperationItem("diagnose", "Diagnose Internet Access", "Run connectivity doctor and deployment checks."),
        ]

        self.install_fields = [
            ("base_domain", "Base Domain", "text"),
            ("listen_addr", "Listen Address", "text"),
            ("install_service", "Install systemd service", "bool"),
            ("proxy_setup", "Configure reverse proxy", "bool"),
            ("proxy_server", "Proxy server", "choice", ["nginx", "apache2"]),
            ("proxy_server_name", "Proxy server name", "text"),
            ("proxy_tls", "Proxy TLS", "bool"),
            ("proxy_cert", "TLS cert path", "text"),
            ("proxy_key", "TLS key path", "text"),
            ("dovecot_auth_mode", "Dovecot auth mode", "choice", ["pam", "sql"]),
            ("dovecot_auth_db_driver", "SQL auth driver", "choice", ["", "mysql", "pgx"]),
            ("dovecot_auth_db_dsn", "SQL auth DSN", "text"),
            ("ufw_enable", "Enable ufw when inactive", "bool"),
            ("ufw_open_proxy_ports", "Open 80/443 in ufw", "bool"),
            ("ufw_open_direct_port", "Open 8080 in ufw", "bool"),
            ("run_diagnose", "Run diagnose at end", "bool"),
            ("auto_install_deps", "Auto-install missing deps", "bool"),
        ]
        self.uninstall_fields = [
            ("backup_env", "Backup /opt/mailclient/.env", "bool"),
            ("backup_data", "Backup /var/lib/mailclient", "bool"),
            ("remove_app_files", "Remove /opt/mailclient", "bool"),
            ("remove_app_data", "Remove /var/lib/mailclient", "bool"),
            ("remove_system_user", "Remove system user", "bool"),
            ("remove_nginx_site", "Remove Nginx site", "bool"),
            ("remove_apache_site", "Remove Apache2 site", "bool"),
            ("remove_checkout", "Remove /opt/mailclient-installer", "bool"),
        ]
        self.ui.status_line = f"Ready. Log file: {self.logstore.log_path}"

    def run(self) -> None:
        curses.curs_set(0)
        self.stdscr.nodelay(False)
        self.stdscr.timeout(120)
        self.stdscr.keypad(True)
        self._init_colors()

        while True:
            self._drain_events()
            self._draw()
            self.ui.spinner_tick += 1
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                key = None

            if key is None:
                continue
            if self._handle_key(key):
                break

    def _init_colors(self) -> None:
        self.has_color = curses.has_colors()
        if not self.has_color:
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_GREEN, -1)
        curses.init_pair(5, curses.COLOR_CYAN, -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)

    def _status_badge(self) -> str:
        service = detect_service_state()
        return f"service:{service} host:{detect_host()} arch:{detect_arch()}"

    def _draw(self) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        if h < 20 or w < 90:
            safe_addstr(self.stdscr, 0, 0, "Terminal too small. Resize to at least 90x20.")
            self.stdscr.refresh()
            return

        safe_addstr(self.stdscr, 0, 2, "DESPATCH TUI :: INSTALL / UNINSTALL / DIAGNOSE", curses.A_BOLD)
        safe_addstr(self.stdscr, 1, 2, self._status_badge())
        safe_addstr(self.stdscr, 2, 2, f"Mode: {self.ui.mode}")

        body_y = 3
        body_h = h - 7
        body_w = w

        if self.ui.mode == "catalog":
            self._draw_catalog(body_y, body_h, body_w)
        elif self.ui.mode == "install_form":
            self._draw_form(body_y, body_h, body_w, "Install Spec", self.install_fields, self.install_spec)
        elif self.ui.mode == "uninstall_form":
            self._draw_form(body_y, body_h, body_w, "Uninstall Spec", self.uninstall_fields, self.uninstall_spec)
        elif self.ui.mode == "run":
            self._draw_run_dashboard(body_y, body_h, body_w)

        self._draw_footer(h - 3, w)
        self.stdscr.refresh()

    def _draw_catalog(self, y: int, h: int, w: int) -> None:
        left_w = max(30, int(w * 0.38))
        right_w = w - left_w

        draw_box(self.stdscr, y, 0, h, left_w, " OPERATIONS ")
        draw_box(self.stdscr, y, left_w, h, right_w, " DETAILS ")

        for idx, op in enumerate(self.operations):
            row = y + 2 + idx
            if row >= y + h - 1:
                break
            marker = ">" if idx == self.ui.selected_operation else " "
            danger = " [danger]" if op.danger else ""
            attr = curses.A_REVERSE if idx == self.ui.selected_operation else 0
            safe_addstr(self.stdscr, row, 2, f"{marker} {op.title}{danger}", attr)

        sel = self.operations[self.ui.selected_operation]
        safe_addstr(self.stdscr, y + 2, left_w + 2, f"Action: {sel.title}", curses.A_BOLD)
        safe_addstr(self.stdscr, y + 4, left_w + 2, sel.summary)
        safe_addstr(self.stdscr, y + 6, left_w + 2, "Press Enter to configure/run.")
        safe_addstr(self.stdscr, y + 7, left_w + 2, "Use j/k or arrows to select operation.")

    def _draw_form(self, y: int, h: int, w: int, title: str, fields: list[tuple], obj: Any) -> None:
        draw_box(self.stdscr, y, 0, h, w, f" {title} ")
        max_rows = h - 5
        start = clamp(self.ui.selected_field - max_rows + 1, 0, max(0, len(fields) - max_rows))

        for i in range(start, min(len(fields), start + max_rows)):
            f = fields[i]
            name = f[0]
            label = f[1]
            ftype = f[2]
            value = getattr(obj, name)
            if isinstance(value, bool):
                value_text = "yes" if value else "no"
            else:
                value_text = str(value)
            attr = curses.A_REVERSE if i == self.ui.selected_field else 0
            safe_addstr(self.stdscr, y + 2 + (i - start), 2, f"{label:<30} {value_text}", attr)

        if self.ui.mode == "install_form":
            errors = self.install_spec.validate()
            if errors:
                safe_addstr(self.stdscr, y + h - 3, 2, f"Validation: {errors[0]}", curses.color_pair(3) | curses.A_BOLD)
            else:
                safe_addstr(self.stdscr, y + h - 3, 2, "Validation: OK", curses.color_pair(4) | curses.A_BOLD)

    def _draw_run_dashboard(self, y: int, h: int, w: int) -> None:
        run = self.run_state
        if run is None:
            draw_box(self.stdscr, y, 0, h, w, " RUN ")
            safe_addstr(self.stdscr, y + 2, 2, "No active run.")
            return

        top_h = max(9, int(h * 0.42))
        bottom_h = h - top_h
        left_w = max(42, int(w * 0.45))
        right_w = w - left_w

        draw_box(self.stdscr, y, 0, top_h, left_w, " STAGES ")
        draw_box(self.stdscr, y, left_w, top_h, right_w, " RUN STATUS ")
        draw_box(self.stdscr, y + top_h, 0, bottom_h, w, " LIVE LOG ")

        ratio = run.overall_progress
        safe_addstr(self.stdscr, y + 1, left_w + 2, f"Run ID: {run.run_id}")
        safe_addstr(self.stdscr, y + 2, left_w + 2, f"Operation: {run.operation}")
        safe_addstr(self.stdscr, y + 3, left_w + 2, f"Status: {run.status}")
        safe_addstr(self.stdscr, y + 4, left_w + 2, f"Progress: {progress_bar(max(20, right_w - 8), ratio)} {int(ratio * 100):3d}%")
        if run.status == "running":
            safe_addstr(self.stdscr, y + 5, left_w + 2, f"Active: {spinner(self.ui.spinner_tick)} {run.active_stage_id}")
        elif run.failed_stage:
            safe_addstr(self.stdscr, y + 5, left_w + 2, f"Failed stage: {run.failed_stage}", curses.color_pair(3) | curses.A_BOLD)
        if run.status == "failed" and self.last_result:
            self._draw_failure_inspector(y + 6, left_w + 2, top_h - 7, right_w - 4)

        rows = top_h - 3
        for idx, stage_id in enumerate(run.stage_order[:rows]):
            stage = run.stages[stage_id]
            if stage.status == "ok":
                icon = "[+]"
                attr = curses.color_pair(4)
            elif stage.status == "failed":
                icon = "[!]"
                attr = curses.color_pair(3)
            elif stage.status == "running":
                icon = f"[{spinner(self.ui.spinner_tick)}]"
                attr = curses.color_pair(5)
            else:
                icon = "[ ]"
                attr = 0
            message = f"{icon} {stage.title}"
            if stage.status == "running" and stage.message:
                message += f" - {stage.message}"
            safe_addstr(self.stdscr, y + 1 + idx, 2, message, attr)

        filtered = self.logstore.filtered(self.ui.log_level_mask, self.ui.log_search)
        viewport = bottom_h - 2
        max_scroll = max(0, len(filtered) - viewport)
        self.ui.run_scroll = clamp(self.ui.run_scroll, 0, max_scroll)
        start = max(0, len(filtered) - viewport - self.ui.run_scroll)
        slice_entries = filtered[start : start + viewport]
        for idx, entry in enumerate(slice_entries):
            attr = 0
            if entry.level == "warn":
                attr = curses.color_pair(2)
            elif entry.level == "error":
                attr = curses.color_pair(3)
            elif entry.level == "debug":
                attr = curses.color_pair(6)
            safe_addstr(self.stdscr, y + top_h + 1 + idx, 2, entry.format_line(), attr)

    def _draw_failure_inspector(self, y: int, x: int, h: int, w: int) -> None:
        if h < 3 or w < 20 or not self.last_result:
            return
        errors = self.last_result.errors
        if not errors:
            safe_addstr(self.stdscr, y, x, "Failure inspector: no detailed errors.")
            return
        primary = errors[0]
        category = self._failure_category(errors)
        safe_addstr(self.stdscr, y, x, f"Failure Inspector [{category}]", curses.A_BOLD)
        safe_addstr(self.stdscr, y + 1, x, f"{primary.code}: {primary.message}"[:w], curses.color_pair(3))
        if primary.suggested_fix:
            safe_addstr(self.stdscr, y + 2, x, f"Fix: {primary.suggested_fix}"[:w], curses.A_DIM)
        for idx, action in enumerate(self.last_result.next_actions[: max(0, h - 4)]):
            safe_addstr(self.stdscr, y + 3 + idx, x, f"- {action}"[:w], curses.A_DIM)

    def _draw_footer(self, y: int, w: int) -> None:
        draw_box(self.stdscr, y, 0, 3, w, " KEYS ")
        if self.ui.mode == "catalog":
            keys = "j/k move | enter open | q quit"
        elif self.ui.mode in {"install_form", "uninstall_form"}:
            keys = "j/k move | enter edit | r run | b back | editor: enter save / esc cancel / ctrl+u clear"
        else:
            keys = "x cancel | r rerun | d diagnose | l levels | / search logs | g/G scroll | e export | b back"
        safe_addstr(self.stdscr, y + 1, 2, keys)
        safe_addstr(self.stdscr, y + 1, max(2, w - min(65, w - 4)), self.ui.status_line[: max(0, w - 6)], curses.A_DIM)

    def _handle_key(self, key: object) -> bool:
        if key in ("q", "Q") and self.ui.mode == "catalog":
            return True

        if self.ui.mode == "catalog":
            return self._handle_catalog_key(key)
        if self.ui.mode == "install_form":
            return self._handle_form_key(key, self.install_fields, self.install_spec)
        if self.ui.mode == "uninstall_form":
            return self._handle_form_key(key, self.uninstall_fields, self.uninstall_spec)
        if self.ui.mode == "run":
            return self._handle_run_key(key)
        return False

    def _handle_catalog_key(self, key: object) -> bool:
        if key in ("j", curses.KEY_DOWN):
            self.ui.selected_operation = clamp(self.ui.selected_operation + 1, 0, len(self.operations) - 1)
            return False
        if key in ("k", curses.KEY_UP):
            self.ui.selected_operation = clamp(self.ui.selected_operation - 1, 0, len(self.operations) - 1)
            return False
        if is_enter(key):
            op = self.operations[self.ui.selected_operation].key
            self.ui.selected_field = 0
            if op == "install":
                self.ui.mode = "install_form"
            elif op == "uninstall":
                self.ui.mode = "uninstall_form"
            else:
                self._start_run("diagnose")
            return False
        return False

    def _handle_form_key(self, key: object, fields: list[tuple], obj: Any) -> bool:
        if key in ("b", "B"):
            self.ui.mode = "catalog"
            self.ui.status_line = "Back to operation catalog."
            return False
        if key in ("j", curses.KEY_DOWN):
            self.ui.selected_field = clamp(self.ui.selected_field + 1, 0, len(fields) - 1)
            return False
        if key in ("k", curses.KEY_UP):
            self.ui.selected_field = clamp(self.ui.selected_field - 1, 0, len(fields) - 1)
            return False
        if key in ("r", "R"):
            if self.ui.mode == "install_form":
                errors = self.install_spec.validate()
                if errors:
                    self.ui.status_line = f"Cannot start: {errors[0]}"
                    return False
                self._start_run("install")
            else:
                self._start_run("uninstall")
            return False
        if is_enter(key):
            field = fields[self.ui.selected_field]
            self._edit_field(obj, field)
            return False
        return False

    def _edit_field(self, obj: Any, field: tuple) -> None:
        name = field[0]
        ftype = field[2]
        current = getattr(obj, name)

        if ftype == "bool":
            next_value = not bool(current)
            if name in {"install_service", "proxy_setup"} and not next_value:
                if not self._confirm_dialog(
                    f"Disable {field[1]}?",
                    "This may prevent service startup or external access.",
                ):
                    self.ui.status_line = f"{name} unchanged"
                    return
            setattr(obj, name, next_value)
            self.ui.status_line = f"{name} set to {getattr(obj, name)}"
            return

        if ftype == "choice":
            selected = self._select_choice(field[1], list(field[3]), str(current))
            if selected is None:
                self.ui.status_line = f"{name} unchanged"
                return
            setattr(obj, name, selected)
            self.ui.status_line = f"{name} set to {selected}"
            return

        value = self._prompt_line(f"{field[1]}", str(current))
        if value is not None:
            setattr(obj, name, value)
            self.ui.status_line = f"{name} updated"

    def _prompt_line(self, label: str, initial: str) -> str | None:
        h, w = self.stdscr.getmaxyx()
        win_h = 5
        win_y = max(0, h - win_h - 1)
        draw_box(self.stdscr, win_y, 2, win_h, w - 4, " INPUT ")
        safe_addstr(self.stdscr, win_y + 1, 4, f"{label}:")
        safe_addstr(self.stdscr, win_y + 3, 4, "Enter=save Esc=cancel Ctrl+U=clear", curses.A_DIM)
        self.stdscr.timeout(-1)
        curses.curs_set(1)
        buf = list(initial)
        cur = len(buf)
        input_x = len(label) + 7
        max_len = max(8, w - input_x - 6)
        try:
            while True:
                text = "".join(buf)
                if len(text) <= max_len:
                    display = text
                    offset = 0
                else:
                    offset = max(0, cur - max_len)
                    display = text[offset : offset + max_len]
                safe_addstr(self.stdscr, win_y + 1, input_x, " " * max_len)
                safe_addstr(self.stdscr, win_y + 1, input_x, display)
                cursor_col = input_x + max(0, min(max_len - 1, cur - offset))
                self.stdscr.move(win_y + 1, cursor_col)
                self.stdscr.refresh()
                key = self.stdscr.get_wch()

                if is_enter(key):
                    return "".join(buf).strip()
                if key in ("\x1b", 27, curses.KEY_EXIT):
                    return None
                if key == "\x15":  # Ctrl+U
                    buf = []
                    cur = 0
                    continue
                if key in (curses.KEY_LEFT, "h"):
                    cur = max(0, cur - 1)
                    continue
                if key in (curses.KEY_RIGHT, "l"):
                    cur = min(len(buf), cur + 1)
                    continue
                if key == curses.KEY_HOME:
                    cur = 0
                    continue
                if key == curses.KEY_END:
                    cur = len(buf)
                    continue
                if key == curses.KEY_DC:
                    if cur < len(buf):
                        del buf[cur]
                    continue
                if is_backspace(key) or key in ("\x7f", "\b"):
                    if cur > 0:
                        cur -= 1
                        del buf[cur]
                    continue
                if isinstance(key, str) and key.isprintable():
                    if len(buf) < 2048:
                        buf.insert(cur, key)
                        cur += 1
                    continue
        except Exception:
            return None
        finally:
            self.stdscr.timeout(120)
            curses.curs_set(0)

    def _select_choice(self, label: str, options: list[str], current: str) -> str | None:
        if not options:
            return None
        h, w = self.stdscr.getmaxyx()
        win_h = min(max(8, len(options) + 4), h - 2)
        win_w = min(max(40, len(label) + 10), w - 4)
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        idx = options.index(current) if current in options else 0
        top = 0
        self.stdscr.timeout(-1)
        try:
            while True:
                draw_box(self.stdscr, y, x, win_h, win_w, f" {label} ")
                viewport = win_h - 4
                if idx < top:
                    top = idx
                if idx >= top + viewport:
                    top = idx - viewport + 1
                for row in range(viewport):
                    opt_i = top + row
                    line_y = y + 2 + row
                    safe_addstr(self.stdscr, line_y, x + 2, " " * (win_w - 4))
                    if opt_i >= len(options):
                        continue
                    opt = options[opt_i]
                    attr = curses.A_REVERSE if opt_i == idx else 0
                    safe_addstr(self.stdscr, line_y, x + 2, opt[: win_w - 5], attr)
                safe_addstr(self.stdscr, y + win_h - 2, x + 2, "Enter=select Esc=cancel", curses.A_DIM)
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if key in ("j", curses.KEY_DOWN):
                    idx = clamp(idx + 1, 0, len(options) - 1)
                    continue
                if key in ("k", curses.KEY_UP):
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

    def _confirm_dialog(self, title: str, detail: str) -> bool:
        h, w = self.stdscr.getmaxyx()
        win_h = 8
        win_w = min(max(56, len(detail) + 6), w - 4)
        y = max(1, (h - win_h) // 2)
        x = max(2, (w - win_w) // 2)
        selected_yes = False
        self.stdscr.timeout(-1)
        try:
            while True:
                draw_box(self.stdscr, y, x, win_h, win_w, " CONFIRM ")
                safe_addstr(self.stdscr, y + 1, x + 2, title[: win_w - 4], curses.A_BOLD)
                safe_addstr(self.stdscr, y + 2, x + 2, detail[: win_w - 4])
                no_attr = curses.A_REVERSE if not selected_yes else 0
                yes_attr = curses.A_REVERSE if selected_yes else 0
                safe_addstr(self.stdscr, y + 5, x + 2, "[ No ]", no_attr)
                safe_addstr(self.stdscr, y + 5, x + 12, "[ Yes ]", yes_attr)
                safe_addstr(self.stdscr, y + 6, x + 2, "Left/Right select, Enter confirm, Esc cancel", curses.A_DIM)
                self.stdscr.refresh()
                key = self.stdscr.get_wch()
                if key in (curses.KEY_LEFT, "h"):
                    selected_yes = False
                    continue
                if key in (curses.KEY_RIGHT, "l"):
                    selected_yes = True
                    continue
                if key in ("y", "Y"):
                    return True
                if key in ("n", "N"):
                    return False
                if is_enter(key):
                    return selected_yes
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
        self.ui.mode = "run"
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
                self.logstore.append("error", "preflight", preflight_error.message)
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
            self.events.put({"type": "log", "level": "info", "stage_id": "summary", "message": f"Summary exported: {summary}"})

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
                # already persisted by runner; no-op here except status update
                message = str(evt.get("message", ""))
                if message:
                    self.ui.status_line = message[:120]
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

    def _handle_run_key(self, key: object) -> bool:
        if key in ("b", "B"):
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run in progress. Cancel first with x."
                return False
            self.ui.mode = "catalog"
            self.ui.status_line = "Back to operation catalog."
            return False

        if key in ("x", "X"):
            if self.cancel_token and self.run_thread and self.run_thread.is_alive():
                self.cancel_token.cancel()
                self.ui.status_line = "Cancellation requested..."
            return False

        if key in ("r", "R"):
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run already in progress."
                return False
            if self.active_operation:
                self._start_run(self.active_operation)
            return False

        if key in ("d", "D"):
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run already in progress."
                return False
            self._start_run("diagnose")
            return False

        if key == "l":
            masks = [
                {"debug", "info", "warn", "error"},
                {"info", "warn", "error"},
                {"warn", "error"},
                {"error"},
            ]
            current = self.ui.log_level_mask
            idx = 0
            for i, m in enumerate(masks):
                if m == current:
                    idx = i
                    break
            self.ui.log_level_mask = masks[(idx + 1) % len(masks)]
            self.ui.status_line = f"Log levels: {','.join(sorted(self.ui.log_level_mask))}"
            return False

        if key == "/":
            query = self._prompt_line("Log search", self.ui.log_search)
            if query is not None:
                self.ui.log_search = query
                self.ui.status_line = f"Log search set: {query or '(none)'}"
            return False

        if key in ("g",):
            self.ui.run_scroll = 999999
            return False

        if key in ("G",):
            self.ui.run_scroll = 0
            return False

        if key == curses.KEY_PPAGE:
            self.ui.run_scroll += 10
            return False

        if key == curses.KEY_NPAGE:
            self.ui.run_scroll = max(0, self.ui.run_scroll - 10)
            return False

        if key in ("e", "E"):
            if self.last_result:
                payload = self.last_summary_payload or self._build_summary_payload(self.active_operation, self.last_result)
                path = self.logstore.export_summary(payload)
                self.ui.status_line = f"Exported summary: {path}"
            else:
                self.ui.status_line = "No run result to export yet."
            return False

        if key in ("q", "Q"):
            if self.run_thread and self.run_thread.is_alive():
                self.ui.status_line = "Run is active. Cancel first with x."
                return False
            return True

        return False

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

    @staticmethod
    def _failure_category(errors: list[RunnerError]) -> str:
        codes = {err.code for err in errors}
        if "UNIT_MISSING" in codes:
            return "UNIT_MISSING"
        if "SERVICE_INACTIVE" in codes:
            return "SERVICE_INACTIVE"
        if "HEALTH_FAIL" in codes:
            return "HEALTH_FAIL"
        if "E_PREFLIGHT" in codes:
            return "E_PREFLIGHT"
        if "E_PROTOCOL" in codes:
            return "E_PROTOCOL"
        if "E_SERVICE" in codes:
            return "E_SERVICE"
        return "GENERAL_FAILURE"


def _main(stdscr: curses.window) -> None:
    app = DespatchTUI(stdscr)
    app.run()



def _prompt_text(label: str, default: str) -> str:
    raw = input(f"{label} [{default}]: ").strip()
    return raw or default


def _prompt_bool(label: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{label} ({hint}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


def run_plain_console() -> int:
    paths = detect_paths()
    runner = OperationRunner(paths)
    logstore = LogStore(max_entries=8000)

    print("Despatch Plain Console")
    print("=====================")
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
            spec.proxy_cert = _prompt_text(
                "TLS cert path", f"/etc/letsencrypt/live/{spec.proxy_server_name}/fullchain.pem"
            )
            spec.proxy_key = _prompt_text(
                "TLS key path", f"/etc/letsencrypt/live/{spec.proxy_server_name}/privkey.pem"
            )
        if spec.dovecot_auth_mode == "sql":
            spec.dovecot_auth_db_driver = _prompt_text("Dovecot SQL driver", "mysql")
            spec.dovecot_auth_db_dsn = _prompt_text("Dovecot SQL DSN", "")

        errors = spec.validate()
        if errors:
            print(f"Validation failed: {errors[0]}")
            return 1

        stage_state = new_run_state("install", f"plain-{int(time.time())}", INSTALL_STAGE_DEFS)
        cancel = CancelToken()

        def on_event(evt: dict[str, Any]) -> None:
            apply_runner_event(stage_state, evt)
            t = evt.get("type", "")
            if t == "stage_start" and evt.get("message") != "pending":
                print(f"\n==> {evt.get('title', evt.get('stage_id', 'stage'))}")
            elif t == "log":
                print(f"[{evt.get('level', 'info')}] {evt.get('message', '')}")
            elif t == "run_result":
                print(f"\nRun result: {evt.get('status')} (exit_code={evt.get('exit_code')})")

        result = runner.run_install(spec, logstore, cancel, on_event)
        print(f"Log file: {logstore.log_path}")
        return 0 if result.status == "ok" else 1

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
        stage_state = new_run_state("uninstall", f"plain-{int(time.time())}", UNINSTALL_STAGE_DEFS)
        cancel = CancelToken()

        def on_event(evt: dict[str, Any]) -> None:
            apply_runner_event(stage_state, evt)
            t = evt.get("type", "")
            if t == "stage_start" and evt.get("message") != "pending":
                print(f"\n==> {evt.get('title', evt.get('stage_id', 'stage'))}")
            elif t == "log":
                print(f"[{evt.get('level', 'info')}] {evt.get('message', '')}")
            elif t == "run_result":
                print(f"\nRun result: {evt.get('status')} (exit_code={evt.get('exit_code')})")

        result = runner.run_uninstall(spec, logstore, cancel, on_event)
        print(f"Log file: {logstore.log_path}")
        return 0 if result.status == "ok" else 1

    if choice == "3":
        stage_state = new_run_state("diagnose", f"plain-{int(time.time())}", DIAG_STAGE_DEFS)
        cancel = CancelToken()

        def on_event(evt: dict[str, Any]) -> None:
            apply_runner_event(stage_state, evt)
            if evt.get("type") == "log":
                print(f"[{evt.get('level', 'info')}] {evt.get('message', '')}")
            elif evt.get("type") == "run_result":
                print(f"\nRun result: {evt.get('status')} (exit_code={evt.get('exit_code')})")

        result = runner.run_diagnose(DiagnoseSpec(), logstore, cancel, on_event)
        print(f"Log file: {logstore.log_path}")
        return 0 if result.status == "ok" else 1

    print("Unknown option.")
    return 1


if __name__ == "__main__":
    if "--plain" in sys.argv:
        raise SystemExit(run_plain_console())
    try:
        curses.wrapper(_main)
    except KeyboardInterrupt:
        pass
