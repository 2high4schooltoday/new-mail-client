#!/usr/bin/env python3
"""Despatch installer/uninstaller terminal dashboard."""

from __future__ import annotations

import curses
import os
import pty
import select
import shutil
import subprocess
import time
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.error import URLError


def _detect_root_dir() -> Path:
    script = Path(__file__).resolve()
    # In-repo layout: <root>/scripts/mailclient_tui.py
    if script.parent.name == "scripts" and (script.parent.parent / "go.mod").exists():
        return script.parent.parent
    # Standalone mode: keep operations in current shell directory.
    return Path.cwd()


ROOT_DIR = _detect_root_dir()
CACHE_DIR = Path.home() / ".cache" / "mailclient-tui"
REMOTE_SCRIPT_BASE = "https://raw.githubusercontent.com/2high4schooltoday/new-mail-client/main/scripts"


@dataclass
class Action:
    key: str
    name: str
    tab: str
    summary: str
    details: list[str]
    local_script: Optional[Path] = None
    remote_script_name: Optional[str] = None
    shell_cmd: Optional[str] = None
    danger: bool = False

    def resolve_command(self) -> tuple[list[str], str]:
        if self.shell_cmd:
            return (["bash", "-lc", self.shell_cmd], "builtin command")

        script_path, source = self._resolve_script()
        return (["bash", str(script_path)], source)

    def _resolve_script(self) -> tuple[Path, str]:
        if self.local_script and self.local_script.exists():
            return (self.local_script, f"local script ({self.local_script})")

        if not self.remote_script_name:
            raise FileNotFoundError("no script source defined")

        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached = CACHE_DIR / self.remote_script_name
        url = f"{REMOTE_SCRIPT_BASE}/{self.remote_script_name}"
        try:
            urllib.request.urlretrieve(url, cached)
        except URLError as exc:
            raise RuntimeError(
                f"failed to fetch {url}: {exc}. "
                "If repo is private, use token-authenticated download or clone the repo first."
            ) from exc
        cached.chmod(0o755)
        return (cached, f"remote script ({url}) cached at {cached}")


class MailclientTUI:
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr = stdscr
        self.tabs = ["Operations", "Tools"]
        self.current_tab = 0
        self.selection = 0
        self.search_mode = False
        self.search_text = ""
        self.last_status_refresh = 0.0
        self.status = {
            "service_unit": False,
            "service_state": "unknown",
            "systemctl": False,
        }

        self.mode = "browse"
        self.run_action: Optional[Action] = None
        self.run_proc: Optional[subprocess.Popen[bytes]] = None
        self.run_master_fd: Optional[int] = None
        self.run_logs: deque[str] = deque(maxlen=4000)
        self.run_partial = ""
        self.run_exit_code: Optional[int] = None
        self.run_scroll_offset = 0

        self.actions = [
            Action(
                key="install",
                name="Install / Upgrade Despatch",
                tab="Operations",
                summary="Runs the interactive auto installer.",
                details=[
                    "Script: scripts/auto_install.sh",
                    "Mode: interactive",
                    "Safe: does not modify Postfix/Dovecot settings directly",
                    "Can auto-configure Nginx or Apache2 reverse proxy",
                ],
                local_script=ROOT_DIR / "scripts" / "auto_install.sh",
                remote_script_name="auto_install.sh",
            ),
            Action(
                key="uninstall",
                name="Uninstall Despatch (Safe)",
                tab="Operations",
                summary="Runs interactive uninstaller with backup prompts.",
                details=[
                    "Script: scripts/uninstall.sh",
                    "Mode: interactive",
                    "Safe: leaves Postfix, Dovecot, and web-server packages intact",
                    "Optionally removes only mailclient site configs",
                ],
                local_script=ROOT_DIR / "scripts" / "uninstall.sh",
                remote_script_name="uninstall.sh",
                danger=True,
            ),
            Action(
                key="status",
                name="Service Status",
                tab="Tools",
                summary="Shows service, unit file, and recent journal entries.",
                details=[
                    "Command: systemctl status mailclient",
                    "Includes: recent journal output (last 50 lines)",
                    "Useful after install or upgrade",
                ],
                shell_cmd="systemctl status mailclient --no-pager || true; echo; journalctl -u mailclient -n 50 --no-pager || true",
            ),
            Action(
                key="ports",
                name="Mail Port Probe",
                tab="Tools",
                summary="Checks local IMAP/SMTP listener ports.",
                details=[
                    "Checks: 143/993 and 25/465/587 on 127.0.0.1",
                    "Command: ss/netstat fallback probe",
                ],
                shell_cmd="if command -v ss >/dev/null 2>&1; then ss -ltnp | awk 'NR==1 || /:25 |:143 |:465 |:587 |:993 /'; else netstat -ltnp 2>/dev/null | awk 'NR==1 || /:25 |:143 |:465 |:587 |:993 /'; fi",
            ),
            Action(
                key="diagnose",
                name="Diagnose Internet Access",
                tab="Tools",
                summary="Runs deployment-aware connectivity checks and root-cause labels.",
                details=[
                    "Script: scripts/diagnose_access.sh",
                    "Reports: APP_DOWN / PROXY_DOWN / PROXY_MISROUTE / PORT_BLOCKED / DNS_MISMATCH",
                    "Safe: read-only diagnostics, no config changes",
                ],
                local_script=ROOT_DIR / "scripts" / "diagnose_access.sh",
                remote_script_name="diagnose_access.sh",
            ),
        ]

    def run(self) -> None:
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        self.stdscr.timeout(60)
        self._init_colors()
        self.refresh_status(force=True)

        while True:
            self._pump_process_output()
            self._draw()
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                continue

            if self.mode == "run":
                if self._handle_run_key(key):
                    break
                continue

            if self._handle_browse_key(key):
                break

    def _init_colors(self) -> None:
        self.has_color = curses.has_colors()
        if not self.has_color:
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_YELLOW)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        curses.init_pair(5, curses.COLOR_WHITE, -1)

    def refresh_status(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self.last_status_refresh < 2.0:
            return
        self.last_status_refresh = now

        self.status["service_unit"] = Path("/etc/systemd/system/mailclient.service").exists()
        self.status["systemctl"] = _have_cmd("systemctl")
        if not self.status["systemctl"]:
            self.status["service_state"] = "n/a"
            return

        try:
            proc = subprocess.run(
                ["systemctl", "is-active", "mailclient"],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            self.status["service_state"] = proc.stdout.strip() or "inactive"
        except Exception:
            self.status["service_state"] = "unknown"

    def _actions_for_current_view(self) -> list[Action]:
        tab = self.tabs[self.current_tab]
        q = self.search_text.lower().strip()
        out: list[Action] = []
        for action in self.actions:
            if action.tab != tab:
                continue
            hay = f"{action.name} {action.summary} {action.key}".lower()
            if q and q not in hay:
                continue
            out.append(action)
        return out

    def _selected_action(self) -> Optional[Action]:
        actions = self._actions_for_current_view()
        if not actions:
            return None
        self.selection = max(0, min(self.selection, len(actions) - 1))
        return actions[self.selection]

    def _handle_browse_key(self, key: object) -> bool:
        if self.search_mode:
            return self._handle_search_input(key)

        if key in ("q", "Q"):
            return True
        if key == "\t":
            self.current_tab = (self.current_tab + 1) % len(self.tabs)
            self.selection = 0
            return False
        if key == "/":
            self.search_mode = True
            self.search_text = ""
            return False
        if key in ("j", curses.KEY_DOWN):
            self.selection += 1
            return False
        if key in ("k", curses.KEY_UP):
            self.selection -= 1
            return False
        if key in ("r", "R"):
            self.refresh_status(force=True)
            return False
        if key in ("\n", curses.KEY_ENTER):
            action = self._selected_action()
            if action:
                self._start_action(action)
            return False
        return False

    def _handle_search_input(self, key: object) -> bool:
        if key in (27,):
            self.search_mode = False
            self.search_text = ""
            self.selection = 0
            return False
        if key in ("\n", curses.KEY_ENTER):
            self.search_mode = False
            self.selection = 0
            return False
        if key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
            self.search_text = self.search_text[:-1]
            self.selection = 0
            return False
        if isinstance(key, str) and key.isprintable():
            self.search_text += key
            self.selection = 0
            return False
        return False

    def _start_action(self, action: Action) -> None:
        self.run_logs.clear()
        self.run_partial = ""
        self.run_exit_code = None
        self.run_scroll_offset = 0
        self.run_action = action

        try:
            cmd, cmd_source = action.resolve_command()
        except Exception as exc:  # pragma: no cover - UI error path
            self.mode = "run"
            self.run_logs.append(f"Failed to prepare command: {exc}")
            self.run_logs.append(f"Working directory: {ROOT_DIR}")
            self.run_logs.append("Press Enter or Esc to return.")
            return

        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT_DIR),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            os.set_blocking(master_fd, False)
            self.run_proc = proc
            self.run_master_fd = master_fd
            self.mode = "run"
            self.run_logs.append(f"Working directory: {ROOT_DIR}")
            self.run_logs.append(f"Command source: {cmd_source}")
            self.run_logs.append(f"$ {' '.join(cmd)}")
            self.run_logs.append("-" * 72)
        except Exception as exc:  # pragma: no cover - UI error path
            self.mode = "run"
            self.run_logs.append(f"Failed to execute command: {exc}")
            self.run_logs.append(f"Working directory: {ROOT_DIR}")
            self.run_logs.append("Press Enter or Esc to return.")

    def _handle_run_key(self, key: object) -> bool:
        running = self.run_proc is not None and self.run_proc.poll() is None

        if running:
            if key == "\x18":  # Ctrl+X
                self._terminate_running_action()
                return False
            if key in (curses.KEY_PPAGE,):
                self.run_scroll_offset = min(self.run_scroll_offset + 10, 100000)
                return False
            if key in (curses.KEY_NPAGE,):
                self.run_scroll_offset = max(self.run_scroll_offset - 10, 0)
                return False
            if key in ("g",):
                self.run_scroll_offset = 100000
                return False
            if key in ("G",):
                self.run_scroll_offset = 0
                return False
            self._forward_key_to_child(key)
            return False

        if key in ("q", "Q", 27, "\n", curses.KEY_ENTER):
            self._cleanup_run_handles()
            self.mode = "browse"
            self.refresh_status(force=True)
            return False
        return False

    def _terminate_running_action(self) -> None:
        if self.run_proc is None:
            return
        try:
            self.run_proc.terminate()
        except Exception:
            pass

    def _forward_key_to_child(self, key: object) -> None:
        if self.run_master_fd is None:
            return
        data: Optional[bytes] = None

        if key in ("\n", curses.KEY_ENTER):
            data = b"\n"
        elif key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
            data = b"\x7f"
        elif key == "\t":
            data = b"\t"
        elif key == curses.KEY_DC:
            data = b"\x1b[3~"
        elif key == curses.KEY_LEFT:
            data = b"\x1b[D"
        elif key == curses.KEY_RIGHT:
            data = b"\x1b[C"
        elif key == curses.KEY_UP:
            data = b"\x1b[A"
        elif key == curses.KEY_DOWN:
            data = b"\x1b[B"
        elif key == 27:
            data = b"\x1b"
        elif isinstance(key, str):
            data = key.encode("utf-8", "replace")

        if data:
            try:
                os.write(self.run_master_fd, data)
            except OSError:
                pass

    def _pump_process_output(self) -> None:
        if self.mode != "run" or self.run_master_fd is None:
            return

        try:
            while True:
                ready, _, _ = select.select([self.run_master_fd], [], [], 0)
                if not ready:
                    break
                chunk = os.read(self.run_master_fd, 4096)
                if not chunk:
                    break
                self._append_log(chunk.decode("utf-8", "replace"))
        except BlockingIOError:
            pass
        except OSError:
            pass

        if self.run_proc is not None and self.run_proc.poll() is not None and self.run_exit_code is None:
            self.run_exit_code = int(self.run_proc.returncode)
            self._append_log(f"\n[exit] command finished with code {self.run_exit_code}")
            if self.run_exit_code != 0:
                self._append_log(
                    "Troubleshooting: check earlier error lines, then run the same command manually in shell."
                )
            self._append_log("Press Enter, Esc, or q to return to the dashboard.")

    def _append_log(self, text: str) -> None:
        for ch in text:
            if ch == "\r":
                self.run_partial = ""
            elif ch == "\n":
                self.run_logs.append(self.run_partial)
                self.run_partial = ""
            else:
                self.run_partial += ch

    def _cleanup_run_handles(self) -> None:
        if self.run_master_fd is not None:
            try:
                os.close(self.run_master_fd)
            except OSError:
                pass
        self.run_master_fd = None
        self.run_proc = None
        self.run_action = None
        self.run_exit_code = None
        self.run_partial = ""

    def _draw(self) -> None:
        self.refresh_status()
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 20 or w < 80:
            self._addn(0, 0, "Terminal too small. Resize to at least 80x20.", max(1, w - 1), self._color(4))
            self.stdscr.refresh()
            return

        header_h = 3
        footer_h = 3
        body_y = header_h
        body_h = h - header_h - footer_h

        self._draw_header(0, 0, header_h, w)
        if self.mode == "browse":
            self._draw_browse(body_y, 0, body_h, w)
        else:
            self._draw_run(body_y, 0, body_h, w)
        self._draw_footer(h - footer_h, 0, footer_h, w)

        self.stdscr.refresh()

    def _draw_header(self, y: int, x: int, h: int, w: int) -> None:
        self._box(y, x, h, w, " DESPATCH TUI ")
        title = "Keyboard-driven installer/uninstaller dashboard"
        runtime = f"service={self.status['service_state']}  unit={'yes' if self.status['service_unit'] else 'no'}"
        self._addn(y + 1, x + 2, title, w - 4, self._color(3))
        self._addn(y + 1, x + max(2, w - len(runtime) - 3), runtime, len(runtime), self._color(5))

    def _draw_browse(self, y: int, x: int, h: int, w: int) -> None:
        left_w = max(30, min(44, int(w * 0.36)))
        right_w = w - left_w
        self._box(y, x, h, left_w, " ACTIONS ")
        self._box(y, x + left_w, h, right_w, " DETAILS ")

        tab_line = "  ".join(
            [f"[{t}]" if i == self.current_tab else t for i, t in enumerate(self.tabs)]
        )
        self._addn(y + 1, x + 2, tab_line, left_w - 4, self._color(3))
        search_label = f"search: {self.search_text}" if self.search_text else "search: (press /)"
        self._addn(y + 2, x + 2, search_label, left_w - 4, self._color(5))

        actions = self._actions_for_current_view()
        if not actions:
            self._addn(y + 4, x + 2, "No actions match current filter.", left_w - 4, self._color(4))
            return

        self.selection = max(0, min(self.selection, len(actions) - 1))
        rows = h - 6
        offset = 0
        if self.selection >= rows:
            offset = self.selection - rows + 1

        for idx, action in enumerate(actions[offset : offset + rows]):
            absolute = idx + offset
            row = y + 4 + idx
            marker = ">" if absolute == self.selection else " "
            state = self._action_state_badge(action)
            line = f"{marker} {action.name}"
            attr = self._color(2) if absolute == self.selection else self._color(5)
            self._addn(row, x + 2, line, left_w - 16, attr)
            self._addn(row, x + left_w - 12, f"[{state}]", 10, self._color(4 if action.danger else 3))

        selected = actions[self.selection]
        self._draw_details_panel(y, x + left_w, h, right_w, selected)

    def _draw_details_panel(self, y: int, x: int, h: int, w: int, action: Action) -> None:
        self._addn(y + 1, x + 2, action.name, w - 4, self._color(3))
        self._addn(y + 2, x + 2, action.summary, w - 4, self._color(5))

        line_y = y + 4
        for detail in action.details:
            for chunk in _wrap(detail, w - 6):
                if line_y >= y + h - 3:
                    return
                self._addn(line_y, x + 2, f"- {chunk}", w - 4, self._color(5))
                line_y += 1

    def _draw_run(self, y: int, x: int, h: int, w: int) -> None:
        title = " LIVE LOG "
        if self.run_action:
            title = f" LIVE LOG :: {self.run_action.name} "
        self._box(y, x, h, w, title)

        hint = (
            "Ctrl+X terminate | PgUp/PgDn scroll logs | g top | G bottom | "
            "installer prompts accept keyboard input."
        )
        self._addn(y + 1, x + 2, hint, w - 4, self._color(3))

        rows = h - 4
        lines = list(self.run_logs)
        if self.run_partial:
            lines = lines + [self.run_partial]
        if self.run_scroll_offset > 0:
            start = max(0, len(lines) - rows - self.run_scroll_offset)
            end = max(0, len(lines) - self.run_scroll_offset)
            lines = lines[start:end]
        else:
            lines = lines[-rows:]
        for idx, line in enumerate(lines):
            self._addn(y + 2 + idx, x + 2, line, w - 4, self._color(5))

    def _draw_footer(self, y: int, x: int, h: int, w: int) -> None:
        self._box(y, x, h, w, " KEYS ")
        if self.mode == "browse":
            if self.search_mode:
                msg = "Type to filter | Enter apply | Esc clear"
            else:
                msg = "j/k or arrows move | Tab switch panel | / search | Enter run | r refresh | q quit"
        else:
            if self.run_proc is not None and self.run_proc.poll() is None:
                msg = "Operation running. Keys forwarded to child. PgUp/PgDn scroll, Ctrl+X terminate."
            else:
                msg = "Operation completed. Enter/Esc/q return to dashboard."
        self._addn(y + 1, x + 2, msg, w - 4, self._color(5))

    def _box(self, y: int, x: int, h: int, w: int, title: str = "") -> None:
        if h < 2 or w < 2:
            return
        self._hline_safe(y, x + 1, curses.ACS_HLINE, w - 2)
        self._hline_safe(y + h - 1, x + 1, curses.ACS_HLINE, w - 2)
        self._vline_safe(y + 1, x, curses.ACS_VLINE, h - 2)
        self._vline_safe(y + 1, x + w - 1, curses.ACS_VLINE, h - 2)
        self._addch_safe(y, x, curses.ACS_ULCORNER)
        self._addch_safe(y, x + w - 1, curses.ACS_URCORNER)
        self._addch_safe(y + h - 1, x, curses.ACS_LLCORNER)
        self._addch_safe(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
        if title:
            self._addn(y, x + 2, title, max(0, w - 4), self._color(3))

    def _addn(self, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
        if width <= 0:
            return
        try:
            self.stdscr.addnstr(y, x, text, width, attr)
        except curses.error:
            pass

    def _addch_safe(self, y: int, x: int, ch: int) -> None:
        try:
            self.stdscr.addch(y, x, ch)
        except curses.error:
            pass

    def _hline_safe(self, y: int, x: int, ch: int, n: int) -> None:
        if n <= 0:
            return
        try:
            self.stdscr.hline(y, x, ch, n)
        except curses.error:
            pass

    def _vline_safe(self, y: int, x: int, ch: int, n: int) -> None:
        if n <= 0:
            return
        try:
            self.stdscr.vline(y, x, ch, n)
        except curses.error:
            pass

    def _color(self, pair: int) -> int:
        if not self.has_color:
            return 0
        return curses.color_pair(pair)

    def _action_state_badge(self, action: Action) -> str:
        if action.key == "install":
            if self.status["service_unit"]:
                if self.status["service_state"] == "active":
                    return "ACTIVE"
                return "UPGRADE"
            return "NEW"
        if action.key == "uninstall":
            if self.status["service_unit"]:
                return "READY"
            return "EMPTY"
        return "TOOLS"


def _wrap(text: str, width: int) -> list[str]:
    if width <= 1:
        return [text]
    out: list[str] = []
    for raw in text.splitlines() or [""]:
        wrapped = []
        start = 0
        while start < len(raw):
            wrapped.append(raw[start : start + width])
            start += width
        if not wrapped:
            wrapped = [""]
        out.extend(wrapped)
    return out


def _have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _main(stdscr: curses.window) -> None:
    app = MailclientTUI(stdscr)
    app.run()


if __name__ == "__main__":
    curses.wrapper(_main)
