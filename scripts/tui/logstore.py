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
    message: str

    def format_line(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.ts))
        stage = self.stage_id or "-"
        return f"{stamp} [{self.level.upper():5}] [{stage}] {self.message}"


class LogStore:
    def __init__(self, max_entries: int = 5000, log_dir: Path | None = None) -> None:
        self.entries: deque[LogEntry] = deque(maxlen=max_entries)
        if log_dir is None:
            preferred = Path("/var/log/despatch")
            if preferred.exists() or preferred.parent.exists():
                log_dir = preferred
            else:
                log_dir = Path.home() / ".cache" / "mailclient-tui"
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        self.log_path = self.log_dir / f"tui-{ts}.log"
        self.summary_path = self.log_dir / f"summary-{ts}.json"

    def append(self, level: str, stage_id: str, message: str, ts: float | None = None) -> LogEntry:
        entry = LogEntry(ts=ts or time.time(), level=level, stage_id=stage_id, message=message)
        self.entries.append(entry)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(entry.format_line())
            fh.write("\n")
        return entry

    def filtered(self, levels: set[str], search: str) -> list[LogEntry]:
        needle = search.lower().strip()
        out: list[LogEntry] = []
        for entry in self.entries:
            if entry.level not in levels:
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
