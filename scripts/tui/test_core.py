from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.tui.models import INSTALL_STAGE_DEFS, InstallSpec
from scripts.tui.state import apply_runner_event, new_run_state


class InstallSpecTests(unittest.TestCase):
    def test_install_spec_validation(self) -> None:
        spec = InstallSpec(base_domain="invalid", proxy_setup=True, proxy_server_name="")
        errs = spec.validate()
        self.assertTrue(errs)

    def test_sql_requires_driver_and_dsn(self) -> None:
        spec = InstallSpec(base_domain="example.com", dovecot_auth_mode="sql", proxy_setup=False)
        errs = spec.validate()
        self.assertTrue(any("driver" in e.lower() for e in errs))
        self.assertTrue(any("dsn" in e.lower() for e in errs))


class StateReducerTests(unittest.TestCase):
    def test_progress_aggregation(self) -> None:
        run = new_run_state("install", "run1", INSTALL_STAGE_DEFS)
        apply_runner_event(run, {"type": "stage_start", "stage_id": "preflight", "message": "started"})
        apply_runner_event(run, {"type": "stage_progress", "stage_id": "preflight", "current": "1", "total": "1", "message": "done"})
        apply_runner_event(run, {"type": "stage_result", "stage_id": "preflight", "status": "ok", "error_code": ""})
        self.assertGreater(run.overall_progress, 0.05)

    def test_run_result_failed(self) -> None:
        run = new_run_state("install", "run1", INSTALL_STAGE_DEFS)
        apply_runner_event(run, {"type": "run_result", "status": "failed", "failed_stage": "deps", "exit_code": "1"})
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.failed_stage, "deps")


if __name__ == "__main__":
    unittest.main()
