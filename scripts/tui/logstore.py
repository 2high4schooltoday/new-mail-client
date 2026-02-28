from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LogEntry:
    ts: float
    level: str
    stage_id: str
    category: str
    message: str

    def format_line(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.ts))
        stage = self.stage_id or "-"
        category = self.category or "system"
        return f"{stamp} [{self.level.upper():5}] [{category}] [{stage}] {self.message}"


class LogStore:
    def __init__(self, max_entries: int = 5000, log_dir: Path | None = None) -> None:
        self.entries: deque[LogEntry] = deque(maxlen=max_entries)
        self.log_dir, fallback_reason = self._resolve_log_dir(log_dir)
        ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        self.log_path = self.log_dir / f"tui-{ts}.log"
        self.summary_path = self.log_dir / f"summary-{ts}.json"
        self.append(
            "info",
            "startup",
            f"log_path={self.log_path}{f' (fallback: {fallback_reason})' if fallback_reason else ''}",
        )

    @staticmethod
    def _resolve_log_dir(log_dir: Path | None) -> tuple[Path, str]:
        fallback = Path.home() / ".cache" / "mailclient-tui" / "logs"
        candidates: list[Path] = []
        if log_dir is not None:
            candidates.append(log_dir)
        else:
            candidates.append(Path("/var/log/despatch"))
            candidates.append(fallback)

        last_err = ""
        for candidate in candidates:
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                # Explicit writability probe.
                probe = candidate / ".write-test"
                with probe.open("w", encoding="utf-8") as fh:
                    fh.write("ok\n")
                probe.unlink(missing_ok=True)
                return candidate, last_err
            except PermissionError as exc:
                last_err = f"permission denied for {candidate}: {exc}"
            except OSError as exc:
                last_err = f"cannot use {candidate}: {exc}"

        # Final guaranteed attempt for caller-provided unwritable path.
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback, last_err or "using fallback log directory"

    def append(
        self,
        level: str,
        stage_id: str,
        message: str,
        ts: float | None = None,
        category: str = "system",
    ) -> LogEntry:
        entry = LogEntry(ts=ts or time.time(), level=level, stage_id=stage_id, category=category, message=message)
        self.entries.append(entry)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(entry.format_line())
            fh.write("\n")
        return entry

    def filtered(self, levels: set[str], search: str, categories: set[str] | None = None) -> list[LogEntry]:
        needle = search.lower().strip()
        out: list[LogEntry] = []
        cat_mask = categories or {"system", "network", "proxy", "service", "auth"}
        for entry in self.entries:
            if entry.level not in levels:
                continue
            if entry.category not in cat_mask:
                continue
            if needle and needle not in entry.format_line().lower():
                continue
            out.append(entry)
        return out

    def export_summary(self, payload: dict) -> Path:
        with self.summary_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return self.summary_path
