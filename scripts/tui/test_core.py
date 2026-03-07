from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.tui.assistant import INSTALL_FLOW, UNINSTALL_FLOW, visible_fields
from scripts.tui.assistant_app import render_progress_preview, render_welcome_preview
from scripts.tui.glyphs import ASCII_GLYPHS, UNICODE_GLYPHS, smooth_bar
from scripts.tui.models import INSTALL_STAGE_DEFS, InstallSpec
from scripts.tui.logstore import LogStore
from scripts.tui.models import AppPaths
from scripts.tui.runner import OperationRunner
from scripts.tui.state import apply_runner_event, new_run_state
from scripts.tui.system_ops import detect_letsencrypt_cert_pair


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

    def test_visible_install_fields_hide_sql_and_tls_dependents(self) -> None:
        spec = InstallSpec(base_domain="example.com", proxy_setup=False, dovecot_auth_mode="pam")
        names = visible_fields("install", INSTALL_FLOW[2], spec)
        self.assertNotIn("dovecot_auth_db_driver", names)
        self.assertNotIn("dovecot_auth_db_dsn", names)
        self.assertNotIn("proxy_cert", names)
        self.assertNotIn("proxy_key", names)

    def test_visible_install_fields_include_sql_and_tls_dependents(self) -> None:
        spec = InstallSpec(
            base_domain="example.com",
            proxy_setup=True,
            proxy_tls=True,
            dovecot_auth_mode="sql",
            dovecot_auth_db_driver="mysql",
            dovecot_auth_db_dsn="dsn",
        )
        names = visible_fields("install", INSTALL_FLOW[2], spec)
        self.assertIn("dovecot_auth_db_driver", names)
        self.assertIn("dovecot_auth_db_dsn", names)
        self.assertIn("proxy_cert", names)
        self.assertIn("proxy_key", names)


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


class GlyphTests(unittest.TestCase):
    def test_unicode_bar_uses_partial_blocks(self) -> None:
        out = smooth_bar(10, 0.35, UNICODE_GLYPHS)
        self.assertEqual(len(out), 10)
        self.assertTrue(any(ch in out for ch in "▏▎▍▌▋▊▉█"))

    def test_ascii_bar_uses_bracket_fallback(self) -> None:
        out = smooth_bar(10, 0.35, ASCII_GLYPHS)
        self.assertTrue(out.startswith("["))
        self.assertTrue(out.endswith("]"))


class PreviewRenderTests(unittest.TestCase):
    def test_welcome_preview_contains_installer_shell(self) -> None:
        lines = render_welcome_preview(120, 34)
        joined = "\n".join(lines)
        self.assertIn("Despatch Installer Assistant", joined)
        self.assertIn("Welcome to the Despatch Installer", joined)
        self.assertIn("Continue", joined)

    def test_progress_preview_can_show_log_drawer(self) -> None:
        lines = render_progress_preview(120, 34, True)
        joined = "\n".join(lines)
        self.assertIn("Installing", joined)
        self.assertIn("Stage timeline", joined)
        self.assertIn("Log", joined)

    def test_compact_preview_still_renders_shell(self) -> None:
        lines = render_welcome_preview(96, 24)
        self.assertEqual(len(lines), 24)
        joined = "\n".join(lines)
        self.assertIn("Install Or Upgrade Despatch", joined)
        self.assertIn("Uninstall", joined)


class LogStoreTests(unittest.TestCase):
    def test_logstore_falls_back_when_preferred_dir_unwritable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            real_mkdir = Path.mkdir

            def fake_mkdir(path_obj: Path, *args: object, **kwargs: object) -> None:
                if str(path_obj) == "/var/log/despatch":
                    raise PermissionError("denied")
                return real_mkdir(path_obj, *args, **kwargs)

            with mock.patch("scripts.tui.logstore.Path.home", return_value=home), mock.patch(
                "scripts.tui.logstore.Path.mkdir",
                new=fake_mkdir,
            ):
                store = LogStore(max_entries=32, log_dir=Path("/var/log/despatch"))
                expected_root = home / ".cache" / "despatch-tui" / "logs"
                self.assertTrue(str(store.log_dir).startswith(str(expected_root)))
                self.assertTrue(store.log_path.exists())

    def test_log_category_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = LogStore(max_entries=32, log_dir=Path(td))
            store.append("info", "proxy", "proxy up", category="proxy")
            store.append("info", "service", "service active", category="service")
            only_proxy = store.filtered({"info"}, "", {"proxy"})
            self.assertEqual(len(only_proxy), 1)
            self.assertEqual(only_proxy[0].category, "proxy")


class RunnerTests(unittest.TestCase):
    def _runner(self, tmp: Path) -> OperationRunner:
        paths = AppPaths(
            root_dir=tmp,
            scripts_dir=tmp,
            install_script=tmp / "auto_install.sh",
            uninstall_script=tmp / "uninstall.sh",
            diagnose_script=tmp / "diagnose_access.sh",
        )
        return OperationRunner(paths)

    def test_missing_run_result_is_protocol_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            runner = self._runner(tmp)
            logstore = LogStore(max_entries=128, log_dir=tmp / "logs")
            spec = InstallSpec(base_domain="example.com", proxy_setup=False, install_service=False)

            def fake_stream(_cmd, _cwd, _env, _cancel, on_line):  # type: ignore[no-untyped-def]
                on_line('::despatch-event::{"type":"stage_result","stage_id":"preflight","status":"ok","error_code":""}')
                return 0

            with mock.patch("scripts.tui.runner.stream_command", new=fake_stream):
                result = runner.run_install(spec, logstore, mock.Mock(cancelled=False), lambda _evt: None)
            self.assertEqual(result.status, "failed")
            self.assertTrue(any(err.code == "E_PROTOCOL" for err in result.errors))

    def test_post_install_verifier_reports_service_error_when_unit_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            runner = self._runner(tmp)
            logstore = LogStore(max_entries=128, log_dir=tmp / "logs")
            spec = InstallSpec(base_domain="example.com", proxy_setup=False, install_service=True)

            def fake_cmd_output(cmd: list[str], timeout: float = 2.0) -> str:
                _ = timeout
                if cmd[:2] == ["systemctl", "list-unit-files"]:
                    return ""
                if cmd[:2] == ["systemctl", "is-active"]:
                    return "inactive"
                return ""

            with mock.patch("scripts.tui.runner.command_output", side_effect=fake_cmd_output), mock.patch(
                "scripts.tui.runner.OperationRunner._http_health_ok",
                return_value=(True, "ok"),
            ):
                verify = runner._verify_install_postchecks(spec, logstore, "run1")
            self.assertFalse(bool(verify["ok"]))
            errs = verify["errors"]
            assert isinstance(errs, list)
            codes = {err.code for err in errs}
            self.assertIn("E_SERVICE", codes)
            self.assertIn("UNIT_MISSING", codes)

    def test_post_install_verifier_accepts_activating_when_health_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            runner = self._runner(tmp)
            logstore = LogStore(max_entries=128, log_dir=tmp / "logs")
            spec = InstallSpec(base_domain="example.com", proxy_setup=False, install_service=True)

            def fake_cmd_output(cmd: list[str], timeout: float = 2.0) -> str:
                _ = timeout
                if cmd[:2] == ["systemctl", "list-unit-files"]:
                    return "despatch.service enabled"
                if cmd[:2] == ["systemctl", "is-active"]:
                    return "activating"
                if cmd[:3] == ["systemctl", "show", "despatch"]:
                    return "start-post"
                return ""

            with mock.patch("scripts.tui.runner.command_output", side_effect=fake_cmd_output), mock.patch(
                "scripts.tui.runner.OperationRunner._http_health_ok",
                return_value=(True, "status=200 body=ok"),
            ):
                verify = runner._verify_install_postchecks(spec, logstore, "run2")

            self.assertTrue(bool(verify["ok"]))

    def test_health_url_for_listen_formats_ipv6(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            runner = self._runner(tmp)
            self.assertEqual(
                runner._health_url_for_listen("[::1]:8080"),
                "http://[::1]:8080/health/live",
            )


class SystemOpsTests(unittest.TestCase):
    def test_detect_letsencrypt_cert_pair_prefers_exact_domain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            live = Path(td)
            exact = live / "mail.example.com"
            fallback = live / "example.com"
            exact.mkdir(parents=True)
            fallback.mkdir(parents=True)
            (exact / "fullchain.pem").write_text("cert", encoding="utf-8")
            (exact / "privkey.pem").write_text("key", encoding="utf-8")
            (fallback / "fullchain.pem").write_text("cert", encoding="utf-8")
            (fallback / "privkey.pem").write_text("key", encoding="utf-8")

            cert, key = detect_letsencrypt_cert_pair("mail.example.com", live)
            self.assertEqual(cert, str(exact / "fullchain.pem"))
            self.assertEqual(key, str(exact / "privkey.pem"))

    def test_detect_letsencrypt_cert_pair_falls_back_to_parent_domain(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            live = Path(td)
            parent = live / "example.com"
            parent.mkdir(parents=True)
            (parent / "fullchain.pem").write_text("cert", encoding="utf-8")
            (parent / "privkey.pem").write_text("key", encoding="utf-8")

            cert, key = detect_letsencrypt_cert_pair("mail.example.com", live)
            self.assertEqual(cert, str(parent / "fullchain.pem"))
            self.assertEqual(key, str(parent / "privkey.pem"))


class FlowDefinitionTests(unittest.TestCase):
    def test_uninstall_flow_has_review_progress_and_completion(self) -> None:
        keys = [step.key for step in UNINSTALL_FLOW]
        self.assertEqual(keys, ["backup", "removal", "review", "progress", "completion"])


if __name__ == "__main__":
    unittest.main()
