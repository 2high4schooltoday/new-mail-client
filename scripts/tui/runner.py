from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Callable

from .logstore import LogStore
from .models import (
    DIAG_STAGE_DEFS,
    INSTALL_STAGE_DEFS,
    UNINSTALL_STAGE_DEFS,
    DiagnoseSpec,
    InstallSpec,
    OperationResult,
    RunnerError,
    StageDef,
    UninstallSpec,
)
from .system_ops import CancelToken, AppPaths, stream_command

EVENT_PREFIX = "::despatch-event::"
LOG_RE = re.compile(r"^\[(INFO|WARN|ERR\s*)\]\s*(.*)$")

EventCb = Callable[[dict], None]


class OperationRunner:
    def __init__(self, paths: AppPaths) -> None:
        self.paths = paths

    def run_install(
        self,
        spec: InstallSpec,
        logstore: LogStore,
        cancel: CancelToken,
        on_event: EventCb,
    ) -> OperationResult:
        cmd = ["bash", str(self.paths.install_script)]
        env = os.environ.copy()
        env.update(spec.to_env())
        return self._run_script(
            operation="install",
            stage_defs=INSTALL_STAGE_DEFS,
            cmd=cmd,
            env=env,
            logstore=logstore,
            cancel=cancel,
            on_event=on_event,
        )

    def run_uninstall(
        self,
        spec: UninstallSpec,
        logstore: LogStore,
        cancel: CancelToken,
        on_event: EventCb,
    ) -> OperationResult:
        cmd = ["bash", str(self.paths.uninstall_script)]
        env = os.environ.copy()
        env.update(spec.to_env())
        return self._run_script(
            operation="uninstall",
            stage_defs=UNINSTALL_STAGE_DEFS,
            cmd=cmd,
            env=env,
            logstore=logstore,
            cancel=cancel,
            on_event=on_event,
        )

    def run_diagnose(
        self,
        _spec: DiagnoseSpec,
        logstore: LogStore,
        cancel: CancelToken,
        on_event: EventCb,
    ) -> OperationResult:
        cmd = ["bash", str(self.paths.diagnose_script)]
        env = os.environ.copy()
        env["DESPATCH_NONINTERACTIVE"] = "1"
        return self._run_script(
            operation="diagnose",
            stage_defs=DIAG_STAGE_DEFS,
            cmd=cmd,
            env=env,
            logstore=logstore,
            cancel=cancel,
            on_event=on_event,
        )

    def _run_script(
        self,
        *,
        operation: str,
        stage_defs: tuple[StageDef, ...],
        cmd: list[str],
        env: dict[str, str],
        logstore: LogStore,
        cancel: CancelToken,
        on_event: EventCb,
    ) -> OperationResult:
        run_id = str(uuid.uuid4())
        env["DESPATCH_TUI_MODE"] = "1"
        env["DESPATCH_RUN_ID"] = run_id

        seen_run_result = False
        seen_stage_result = False
        errors: list[RunnerError] = []
        active_stage = stage_defs[0].stage_id if stage_defs else ""

        on_event({"type": "run_start", "run_id": run_id, "operation": operation})

        for stage in stage_defs:
            # Prime UI with deterministic stage catalog.
            on_event(
                {
                    "type": "stage_start",
                    "stage_id": stage.stage_id,
                    "title": stage.title,
                    "weight": str(stage.weight),
                    "message": "pending",
                }
            )
            on_event(
                {
                    "type": "stage_progress",
                    "stage_id": stage.stage_id,
                    "current": "0",
                    "total": "1",
                    "message": "pending",
                }
            )

        # Reset first stage to running so UI doesn't show only pending states.
        if stage_defs:
            on_event(
                {
                    "type": "stage_start",
                    "stage_id": stage_defs[0].stage_id,
                    "title": stage_defs[0].title,
                    "weight": str(stage_defs[0].weight),
                    "message": "started",
                }
            )

        def on_line(line: str) -> None:
            nonlocal seen_run_result, seen_stage_result, active_stage
            if line.startswith(EVENT_PREFIX):
                payload = line[len(EVENT_PREFIX) :].strip()
                try:
                    evt = json.loads(payload)
                    evt_type = str(evt.get("type", ""))
                    if evt_type == "stage_start":
                        active_stage = str(evt.get("stage_id", active_stage))
                    if evt_type == "stage_result":
                        seen_stage_result = True
                    if evt_type == "run_result":
                        seen_run_result = True
                    on_event(evt)
                except json.JSONDecodeError:
                    logstore.append("warn", active_stage, f"Malformed event: {payload}")
                return

            level = "info"
            message = line
            match = LOG_RE.match(line)
            if match:
                raw = match.group(1).strip().lower()
                message = match.group(2)
                if raw.startswith("err"):
                    level = "error"
                elif raw == "warn":
                    level = "warn"
                else:
                    level = "info"
            if "[non-interactive]" in message:
                level = "debug"
            entry = logstore.append(level, active_stage, message)
            on_event(
                {
                    "type": "log",
                    "level": entry.level,
                    "stage_id": active_stage,
                    "message": entry.message,
                    "ts": str(entry.ts),
                }
            )
            if level == "error":
                errors.append(
                    RunnerError(
                        code="E_COMMAND",
                        message=entry.message,
                        stage_id=active_stage,
                        suggested_fix="Inspect log and retry the operation.",
                    )
                )

        exit_code = stream_command(cmd, self.paths.root_dir, env, cancel, on_line)

        if cancel.cancelled:
            on_event({"type": "run_result", "status": "cancelled", "failed_stage": active_stage, "exit_code": "130"})
            return OperationResult(
                status="cancelled",
                errors=[RunnerError("E_CANCELLED", "Operation cancelled by operator.", active_stage)],
                artifacts={
                    "full_log": str(logstore.log_path),
                },
                next_actions=["Re-run operation when ready."],
            )

        if not seen_stage_result and active_stage:
            on_event(
                {
                    "type": "stage_progress",
                    "stage_id": active_stage,
                    "current": "1",
                    "total": "1",
                    "message": "done" if exit_code == 0 else "failed",
                }
            )
            on_event(
                {
                    "type": "stage_result",
                    "stage_id": active_stage,
                    "status": "ok" if exit_code == 0 else "failed",
                    "error_code": "" if exit_code == 0 else "E_COMMAND",
                }
            )

        if not seen_run_result:
            status = "ok" if exit_code == 0 else "failed"
            on_event(
                {
                    "type": "run_result",
                    "status": status,
                    "failed_stage": "" if exit_code == 0 else active_stage,
                    "exit_code": str(exit_code),
                }
            )

        if exit_code == 0:
            return OperationResult(
                status="ok",
                artifacts={
                    "full_log": str(logstore.log_path),
                },
                next_actions=["Open web UI and verify OOBE/mail access."],
            )

        if not errors:
            errors.append(
                RunnerError(
                    code="E_COMMAND",
                    message=f"Command exited with code {exit_code}",
                    stage_id=active_stage,
                    suggested_fix="Open Failure Inspector and run suggested checks.",
                )
            )

        return OperationResult(
            status="failed",
            errors=errors,
            artifacts={
                "full_log": str(logstore.log_path),
            },
            next_actions=[
                "Review failure inspector details.",
                "Run diagnostics from the tool catalog.",
            ],
        )
