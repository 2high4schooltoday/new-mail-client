from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import RunState, StageDef, StageState


@dataclass
class UIState:
    mode: str = "catalog"
    selected_operation: int = 0
    selected_field: int = 0
    status_line: str = "Ready."
    log_level_mask: set[str] = field(default_factory=lambda: {"debug", "info", "warn", "error"})
    log_search: str = ""
    run_scroll: int = 0
    spinner_tick: int = 0


def new_run_state(operation: str, run_id: str, stage_defs: tuple[StageDef, ...]) -> RunState:
    stages = {
        s.stage_id: StageState(stage_id=s.stage_id, title=s.title, weight=s.weight)
        for s in stage_defs
    }
    return RunState(
        run_id=run_id,
        operation=operation,  # type: ignore[arg-type]
        status="running",
        stages=stages,
        stage_order=[s.stage_id for s in stage_defs],
        active_stage_id="",
    )


def apply_runner_event(run_state: RunState, event: dict[str, Any]) -> None:
    etype = str(event.get("type", ""))

    if etype == "run_start":
        run_state.status = "running"
        run_state.operation = event.get("operation", run_state.operation)
        run_state.run_id = str(event.get("run_id", run_state.run_id))
        return

    if etype == "stage_start":
        stage_id = str(event.get("stage_id", ""))
        if stage_id and stage_id in run_state.stages:
            stage = run_state.stages[stage_id]
            msg = str(event.get("message", "started"))
            stage.status = "pending" if msg == "pending" else "running"
            stage.current = 0
            stage.total = 1
            stage.message = msg
            if stage.status == "running":
                run_state.active_stage_id = stage_id
        return

    if etype == "stage_progress":
        stage_id = str(event.get("stage_id", ""))
        if stage_id and stage_id in run_state.stages:
            stage = run_state.stages[stage_id]
            msg = str(event.get("message", stage.message))
            if msg == "pending" and stage.status == "pending":
                stage.status = "pending"
            else:
                stage.status = "running"
            try:
                stage.current = int(float(str(event.get("current", stage.current))))
                stage.total = max(1, int(float(str(event.get("total", stage.total)))))
            except Exception:
                pass
            stage.message = msg
            stage.rate_hint = str(event.get("rate_hint", stage.rate_hint))
            stage.eta_hint = str(event.get("eta_hint", stage.eta_hint))
            if stage.status == "running":
                run_state.active_stage_id = stage_id
        return

    if etype == "stage_result":
        stage_id = str(event.get("stage_id", ""))
        if stage_id and stage_id in run_state.stages:
            stage = run_state.stages[stage_id]
            status = str(event.get("status", "ok"))
            if status in {"ok", "failed", "skipped"}:
                stage.status = status  # type: ignore[assignment]
            else:
                stage.status = "ok"
            stage.error_code = str(event.get("error_code", ""))
            if stage.status in {"ok", "skipped"}:
                stage.current = max(stage.current, stage.total)
            if stage.status == "failed":
                run_state.failed_stage = stage_id
                run_state.status = "failed"
        return

    if etype == "run_result":
        status = str(event.get("status", "failed"))
        run_state.failed_stage = str(event.get("failed_stage", run_state.failed_stage))
        try:
            run_state.exit_code = int(str(event.get("exit_code", run_state.exit_code)))
        except Exception:
            pass
        if status == "ok":
            run_state.status = "ok"
        elif status == "partial":
            run_state.status = "partial"
        elif status == "cancelled":
            run_state.status = "cancelled"
        else:
            run_state.status = "failed"
        if run_state.status != "running":
            run_state.active_stage_id = ""
        return
