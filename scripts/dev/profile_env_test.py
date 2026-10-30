#!/usr/bin/env python3
"""Hermetic tests for profile_env.py. No Effigy, containers or external network."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import profile_env  # noqa: E402

DECLARED = {
    "api": "api.acme.test",
    "front": "acme.test",
    "admin": "admin.acme.test",
    "s3": "s3.acme.test",
}


def route(kind: str, declared: str, effective: str, service: str | None = None) -> dict:
    entry = {"kind": kind, "declared": declared, "effective": effective, "service": service}
    if kind == "http":
        entry["origin"] = f"https://{effective}"
    return entry


STATUS = {
    "services": [
        {"name": "dbgate", "ports": ["127.0.0.1:11930->3000/tcp"]},
        {"name": "postgres", "ports": ["127.0.0.1:11932->5432/tcp"]},
        {"name": "silo", "ports": ["127.0.0.1:11940-11941->9000-9001/tcp"]},
        {"name": "mailpit", "ports": ["127.0.0.1:11925->8025", "11926->1025/tcp"]},
    ]
}


def report(scope: str = "") -> dict:
    """Shape of `effigy container hybrid hosts --json` for a scoped checkout."""
    apex = f"acme{scope}.test"
    return {
        "cookie_domain": f"s3.{apex}",
        "routes": [
            route("http", "s3.acme.test", f"s3.{apex}", "silo"),
            route("http", "dbgate.acme.test", f"dbgate.{apex}", "dbgate"),
            route("tcp", "smtp.s3.acme.test", f"smtp.s3.{apex}", "mailpit"),
            route("tcp", "postgres.s3.acme.test", f"postgres.s3.{apex}", "postgres"),
            route("http", "api.acme.test", f"api.{apex}"),
            route("http", "acme.test", apex),
            route("http", "admin.acme.test", f"admin.{apex}"),
        ],
    }


class AppEnvironmentTest(unittest.TestCase):
    def test_primary_checkout_uses_declared_names(self) -> None:
        env = profile_env.app_environment(report(), STATUS, DECLARED, "acme")
        self.assertEqual(env["PUBLIC_HOST"], "api.acme.test")
        self.assertEqual(env["PUBLIC_PORT"], "443")
        self.assertEqual(env["CORS_ORIGINS"], "https://acme.test,https://admin.acme.test")
        self.assertEqual(env["COOKIE_DOMAIN"], ".acme.test")
        self.assertEqual(env["DATABASE_URL"], "postgres://postgres:secret@127.0.0.1:11932/acme")
        self.assertEqual((env["SMTP_HOST"], env["SMTP_PORT"]), ("127.0.0.1", "11926"))
        self.assertEqual(env["EFFIGY_PROFILE_S3_ENDPOINT"], "http://127.0.0.1:11940")
        self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "minioadmin")
        self.assertEqual(env["EFFIGY_PROFILE_S3_PUBLIC_URL"], "https://s3.acme.test")

    def test_worktree_uses_effective_names_everywhere(self) -> None:
        env = profile_env.app_environment(report("-w1234abcd"), STATUS, DECLARED, "acme")
        self.assertEqual(env["PUBLIC_HOST"], "api.acme-w1234abcd.test")
        self.assertEqual(env["COOKIE_DOMAIN"], ".acme-w1234abcd.test")
        for value in env.values():
            self.assertNotIn("//acme.test", value)

    def test_nonstandard_gateway_port_reaches_public_urls(self) -> None:
        moved = report()
        for entry in moved["routes"]:
            if entry["kind"] == "http":
                entry["origin"] += ":8443"
        env = profile_env.app_environment(moved, STATUS, DECLARED, "acme")
        self.assertEqual(env["PUBLIC_PORT"], "8443")
        self.assertEqual(env["EFFIGY_PROFILE_GATEWAY_HTTPS_PORT"], "8443")

    def test_missing_route_or_alias_refuses(self) -> None:
        without_admin = report()
        without_admin["routes"] = [r for r in without_admin["routes"] if r["declared"] != "admin.acme.test"]
        with self.assertRaisesRegex(profile_env.ProfileError, "admin"):
            profile_env.app_environment(without_admin, STATUS, DECLARED, "acme")
        without_postgres = {"services": [e for e in STATUS["services"] if e["name"] != "postgres"]}
        with self.assertRaisesRegex(profile_env.ProfileError, "postgres"):
            profile_env.app_environment(report(), without_postgres, DECLARED, "acme")

    def test_published_port_handles_ranges_and_bare_mappings(self) -> None:
        self.assertEqual(profile_env.published_port(STATUS, "silo", 9001), 11941)
        self.assertEqual(profile_env.published_port(STATUS, "mailpit", 8025), 11925)
        with self.assertRaises(profile_env.ProfileError):
            profile_env.published_port(STATUS, "silo", 9002)

    def test_custom_front_label_still_finds_apex(self) -> None:
        self.assertEqual(profile_env.shared_apex(["api.acme.test", "www.acme.test", "admin.acme.test"]), "acme.test")
        with self.assertRaises(profile_env.ProfileError):
            profile_env.shared_apex(["api.acme.test", "admin.other.dev"])


class ExecSeamTest(unittest.TestCase):
    """The supervisor's HOST/PORT must reach the app through the real exec seam.

    A fake `effigy` stands in for the nested selector boundary: it records the
    environment it receives and spawns the task that selector would run. The
    queries it answers are Effigy's report envelopes, so `profile_env.py`
    runs its production `exec` path unchanged.
    """

    FAKE_EFFIGY = '''#!__PYTHON__
import json, os, subprocess, sys
HOSTS = json.loads(__HOSTS__)
STATUS = json.loads(__STATUS__)
args = sys.argv[1:]
if args[-2:] == ["hosts", "--json"]:
    print(json.dumps({"ok": True, "result": HOSTS}))
elif args[-2:] == ["status", "--json"]:
    print(json.dumps({"ok": True, "result": STATUS}))
else:
    record = {
        "stage": "selector",
        "argv": args,
        "HOST": os.environ.get("HOST"),
        "PORT": os.environ.get("PORT"),
        "PUBLIC_HOST": os.environ.get("PUBLIC_HOST"),
        "API_PUBLIC_URL": os.environ.get("EFFIGY_PROFILE_API_PUBLIC_URL"),
    }
    with open(__OUT__, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    task = subprocess.run([
        sys.executable,
        "-c",
        "import json,os,sys; json.dump({'HOST': os.environ.get('HOST'), 'PORT': os.environ.get('PORT')}, open(sys.argv[1], 'w'))",
        __OUT__ + ".task",
    ])
    sys.exit(7 if task.returncode == 0 else task.returncode)
'''

    def test_host_and_port_survive_exec_and_the_nested_selector(self) -> None:
        import http.server
        import json
        import os
        import socket
        import subprocess
        import tempfile
        import threading

        class Ready(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args: object) -> None:
                pass

        def listening_port() -> int:
            sock = socket.socket()
            self.addCleanup(sock.close)
            sock.bind(("127.0.0.1", 0))
            sock.listen(8)
            return sock.getsockname()[1]

        silo = http.server.HTTPServer(("127.0.0.1", 0), Ready)
        threading.Thread(target=silo.serve_forever, daemon=True).start()
        self.addCleanup(silo.server_close)
        self.addCleanup(silo.shutdown)
        postgres, mailpit = listening_port(), listening_port()
        status = {
            "services": [
                {"name": "postgres", "ports": [f"127.0.0.1:{postgres}->5432/tcp"]},
                {"name": "mailpit", "ports": [f"127.0.0.1:{mailpit}->1025/tcp"]},
                {"name": "silo", "ports": [f"127.0.0.1:{silo.server_port}->9000/tcp"]},
            ]
        }

        with tempfile.TemporaryDirectory() as root:
            out = Path(root, "selector.json")
            bin_dir = Path(root, "bin")
            bin_dir.mkdir()
            fake = bin_dir / "effigy"
            fake.write_text(
                self.FAKE_EFFIGY.replace("__PYTHON__", sys.executable)
                .replace("__HOSTS__", repr(json.dumps(report())))
                .replace("__STATUS__", repr(json.dumps(status)))
                .replace("__OUT__", json.dumps(str(out))),
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("EFFIGY_INTERNAL_", "EFFIGY_MANAGED_HOST_"))
            }
            env.update({
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "EFFIGY_PROFILE_REPO": root,
                "EFFIGY_PROFILE_DATABASE": "acme",
                "EFFIGY_PROFILE_API_DECLARED": "api.acme.test",
                "EFFIGY_PROFILE_FRONT_DECLARED": "acme.test",
                "EFFIGY_PROFILE_ADMIN_DECLARED": "admin.acme.test",
                "EFFIGY_PROFILE_S3_DECLARED": "s3.acme.test",
                "NODE_EXTRA_CA_CERTS": str(Path(root, "ca.pem")),
                "HOST": "127.0.0.1",
                "PORT": "43123",
            })
            command = [
                sys.executable,
                str(Path(__file__).with_name("profile_env.py")),
                "exec", "hybrid", "--", "effigy", "profile:api",
            ]
            proc = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 7, proc.stdout + proc.stderr)
            selector = json.loads(out.read_text(encoding="utf-8"))
            task = json.loads(Path(str(out) + ".task").read_text(encoding="utf-8"))

        self.assertEqual(selector["argv"], ["profile:api"])
        self.assertEqual((selector["HOST"], selector["PORT"]), ("127.0.0.1", "43123"))
        self.assertEqual(selector["PUBLIC_HOST"], "api.acme.test")
        self.assertEqual(selector["API_PUBLIC_URL"], "https://api.acme.test")
        self.assertEqual((task["HOST"], task["PORT"]), ("127.0.0.1", "43123"))


class ServiceWaitTest(unittest.TestCase):
    def test_waits_until_every_probe_passes(self) -> None:
        calls: list[int] = []

        def becomes_ready(after: int):
            def probe(port: int) -> bool:
                calls.append(port)
                return calls.count(port) > after
            return probe

        profile_env.wait_for_services(
            STATUS,
            {"postgres": (5432, becomes_ready(1)), "silo": (9000, becomes_ready(3))},
            sleep=lambda _: None,
        )
        self.assertEqual(calls.count(11940), 4)
        self.assertEqual(calls.count(11932), 2)

    def test_times_out_naming_the_service(self) -> None:
        now = iter(range(0, 1000, 10))
        with self.assertRaisesRegex(profile_env.ProfileError, "silo"):
            profile_env.wait_for_services(
                STATUS, {"silo": (9000, lambda port: False)}, timeout=30,
                clock=lambda: next(now), sleep=lambda _: None,
            )


class GatewayCaTest(unittest.TestCase):
    def test_private_gateway_ca_comes_from_its_state_root(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "ca").mkdir()
            (Path(root) / "ca" / "rootCA.pem").write_text("pem")
            self.assertEqual(
                profile_env.gateway_ca_file({"EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": root}),
                str(Path(root) / "ca" / "rootCA.pem"),
            )

    def test_shared_gateway_uses_the_mkcert_root(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as caroot:
            (Path(caroot) / "rootCA.pem").write_text("pem")
            self.assertEqual(
                profile_env.gateway_ca_file({}, mkcert_caroot=caroot),
                str(Path(caroot) / "rootCA.pem"),
            )
            self.assertIsNone(profile_env.gateway_ca_file({}, mkcert_caroot=caroot + "-missing"))


class BootstrapTest(unittest.TestCase):
    def test_cors_grants_exactly_the_given_origins(self) -> None:
        script = profile_env.bootstrap_script("acme-media", ["https://acme-wx.test", "https://admin.acme-wx.test"])
        self.assertIn("<AllowedOrigin>https://acme-wx.test</AllowedOrigin>", script)
        self.assertIn("<AllowedOrigin>https://admin.acme-wx.test</AllowedOrigin>", script)
        self.assertEqual(script.count("<AllowedOrigin>"), 2)
        self.assertIn("mc mb local/acme-media --ignore-existing", script)
        self.assertIn("mc anonymous set download local/acme-media", script)

    def test_bootstrap_requires_bucket(self) -> None:
        with self.assertRaisesRegex(profile_env.ProfileError, "BUCKET"):
            profile_env.bootstrap(Path("/repo"), "hybrid", {})


class DevTestCycleTest(unittest.TestCase):
    def test_empty_task_refuses_before_any_effigy_call(self) -> None:
        with mock.patch.object(profile_env, "effigy") as effigy:
            with self.assertRaisesRegex(profile_env.ProfileError, "profiles.test_task"):
                profile_env.run_test(Path("/repo"), "test", "", 60, {})
            effigy.assert_not_called()

    def test_failed_startup_still_tears_down(self) -> None:
        failed = mock.Mock(returncode=1, stderr="boom", stdout="")
        ok = mock.Mock(returncode=0, stderr="", stdout="")
        with mock.patch.object(profile_env, "effigy", side_effect=[ok, failed, ok]) as effigy:
            with self.assertRaisesRegex(profile_env.ProfileError, "up failed"):
                profile_env.run_test(Path("/repo"), "test", "acme-api/test", 60, {})
        calls = [call.args[1:] for call in effigy.call_args_list]
        self.assertEqual(calls[0], ("container", "test", "reset"))
        self.assertEqual(calls[-1], ("container", "test", "down"))

    def test_timeout_returns_124_and_tears_down(self) -> None:
        ok = mock.Mock(returncode=0, stderr="", stdout="")
        with mock.patch.object(profile_env, "effigy", return_value=ok) as effigy, \
             mock.patch.object(profile_env, "bootstrap"), \
             mock.patch.object(profile_env, "resolved_environment", return_value={}), \
             mock.patch.object(profile_env.subprocess, "run",
                               side_effect=profile_env.subprocess.TimeoutExpired("effigy", 1)):
            self.assertEqual(profile_env.run_test(Path("/repo"), "test", "acme-api/test", 1, {}), 124)
        self.assertEqual(effigy.call_args_list[-1].args[1:], ("container", "test", "down"))


class DevSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(profile_env, "vault_status", return_value="unlocked")
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_quitting_the_tui_always_stops_the_stack(self) -> None:
        tui = mock.Mock(**{"wait.return_value": 3})
        with mock.patch.object(profile_env.subprocess, "Popen", return_value=tui) as popen, \
             mock.patch.object(profile_env.signal, "signal"), \
             mock.patch.object(profile_env.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run:
            self.assertEqual(profile_env.run_dev(Path("/repo"), "hybrid", "dev:hybrid:tui"), 3)
        self.assertEqual(popen.call_args.args[0][0], "effigy")
        self.assertEqual(popen.call_args.args[0][-1], "dev:hybrid:tui")
        self.assertLess(popen.call_args.args[0].index("--repo"), popen.call_args.args[0].index("dev:hybrid:tui"))
        self.assertEqual(run.call_args.args[0][-3:], ["container", "hybrid", "down"])
        self.assertEqual(run.call_args.args[0][1], "--repo")

    def test_interrupt_during_the_tui_still_stops_the_stack(self) -> None:
        tui = mock.Mock(**{"wait.side_effect": [KeyboardInterrupt, 0]})
        with mock.patch.object(profile_env.subprocess, "Popen", return_value=tui), \
             mock.patch.object(profile_env.signal, "signal"), \
             mock.patch.object(profile_env.subprocess, "run", return_value=mock.Mock(returncode=1, stdout="", stderr="")) as run:
            self.assertEqual(profile_env.run_dev(Path("/repo"), "hybrid", "dev:hybrid:tui"), 1)
        run.assert_called_once()

    def test_failed_start_keeps_the_services_tab_open(self) -> None:
        class Quit(Exception):
            pass

        def idle():
            raise Quit

        with mock.patch.object(profile_env.subprocess, "run", return_value=mock.Mock(returncode=2)), \
             mock.patch.object(profile_env, "effigy") as effigy, \
             mock.patch.object(profile_env.signal, "signal"):
            with self.assertRaises(Quit):
                profile_env.run_session(Path("/repo"), "hybrid", "dev:hybrid", idle=idle)
            effigy.assert_not_called()


class VaultUnlockTest(unittest.TestCase):
    def test_locked_vault_unlocks_before_the_tui(self) -> None:
        order = []
        tui = mock.Mock(**{"wait.return_value": 0})
        with mock.patch.object(profile_env, "vault_status", return_value="locked"), \
             mock.patch.object(profile_env.signal, "signal"), \
             mock.patch.object(profile_env.subprocess, "Popen", side_effect=lambda *a, **k: order.append("tui") or tui), \
             mock.patch.object(profile_env.subprocess, "run", side_effect=lambda argv, **k: order.append(argv[3:]) or mock.Mock(returncode=0)):
            self.assertEqual(profile_env.run_dev(Path("/repo"), "hybrid", "dev:hybrid:tui"), 0)
        self.assertEqual(order[0], ["secrets", "unlock"])
        self.assertEqual(order[1], "tui")

    def test_failed_unlock_never_opens_the_tui(self) -> None:
        with mock.patch.object(profile_env, "vault_status", return_value="locked"), \
             mock.patch.object(profile_env.subprocess, "Popen") as popen, \
             mock.patch.object(profile_env.subprocess, "run", return_value=mock.Mock(returncode=1)):
            self.assertEqual(profile_env.run_dev(Path("/repo"), "hybrid", "dev:hybrid:tui"), 1)
        popen.assert_not_called()

    def test_unlocked_or_unknown_vault_skips_unlock(self) -> None:
        for state in ("unlocked", None):
            with mock.patch.object(profile_env, "vault_status", return_value=state):
                with mock.patch.object(profile_env.subprocess, "run") as run:
                    self.assertEqual(profile_env.ensure_vault_unlocked(Path("/repo")), 0)
                run.assert_not_called()


class FollowLogTest(unittest.TestCase):
    def test_streams_only_output_written_after_the_tab_opens(self) -> None:
        import io
        import tempfile

        class Stop(Exception):
            pass

        with tempfile.TemporaryDirectory() as repo:
            log = Path(repo, ".effigy/runtime/host-processes/hybrid/effigy/api.log")
            log.parent.mkdir(parents=True)
            log.write_text("previous run\n")
            out = io.StringIO()
            appends = iter(["   Compiling api\n"])

            def sleep(_):
                try:
                    with log.open("a") as handle:
                        handle.write(next(appends))
                except StopIteration:
                    raise Stop

            with self.assertRaises(Stop):
                profile_env.follow_log(Path(repo), "hybrid", "api", out=out, sleep=sleep)
            self.assertEqual(out.getvalue(), "   Compiling api\n")

    def test_waits_for_a_process_that_has_not_started(self) -> None:
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            out = io.StringIO()
            profile_env.follow_log(Path(repo), "hybrid", "jobs", out=out, forever=False)
            self.assertIn("waiting for `jobs`", out.getvalue())

    def _drive_follow(self, repo: str, process: str, steps: list) -> str:
        """Run follow_log while each sleep call applies the next mutation."""
        import io

        class Stop(Exception):
            pass

        out = io.StringIO()
        pending = iter(steps)

        def sleep(_):
            try:
                mutation = next(pending)
            except StopIteration:
                raise Stop
            mutation()

        with self.assertRaises(Stop):
            profile_env.follow_log(Path(repo), "hybrid", process, out=out, sleep=sleep)
        return out.getvalue()

    def _process_log(self, repo: str, process: str = "api") -> Path:
        log = Path(repo, ".effigy/runtime/host-processes/hybrid/effigy", f"{process}.log")
        log.parent.mkdir(parents=True)
        return log

    def test_normal_appends_stream_without_repeating_old_bytes(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_text("previous run\n")
            text = self._drive_follow(repo, "api", [
                lambda: log.write_text("previous run\n   Compiling api\n"),
                lambda: log.write_text("previous run\n   Compiling api\n    Finished\n"),
            ])
            self.assertEqual(text, "   Compiling api\n    Finished\n")
            self.assertNotIn("previous run", text)

    def test_observed_shrink_restarts_from_zero_with_one_marker(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"old-generation-bytes")
            marker = profile_env.LOG_RESTART_MARKER
            text = self._drive_follow(repo, "api", [
                lambda: log.write_bytes(b"new\n"),
                lambda: None,
            ])
            self.assertEqual(text, marker + "new\n")
            self.assertNotIn("old-generation", text)

    def test_inode_replacement_reads_new_file_from_zero(self) -> None:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"old-bytes-01234567")
            new_content = b"NEW-LOG-CONTENT-0123456789"
            self.assertGreaterEqual(len(new_content), 18)

            def quarantine_and_replace() -> None:
                staged = log.with_name("api.log.staged")
                staged.write_bytes(new_content)
                os.replace(staged, log)

            marker = profile_env.LOG_RESTART_MARKER
            text = self._drive_follow(repo, "api", [quarantine_and_replace, lambda: None])
            # Without identity tracking the follower would seek to the saved
            # offset inside the new file and emit only its tail.
            self.assertEqual(text, marker + new_content.decode())
            self.assertNotIn("old-bytes", text)

    def test_replacement_between_stat_and_open_reads_new_bytes(self) -> None:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"old-bytes-01234567")
            new_content = b"cutover-bytes-here!!"
            real_open = Path.open
            swapped: list[bool] = []

            def swapping_open(self, *args, **kwargs):
                if not swapped and Path(self) == log:
                    swapped.append(True)
                    staged = log.with_name("api.log.staged")
                    staged.write_bytes(new_content)
                    os.replace(staged, log)
                return real_open(self, *args, **kwargs)

            import io
            out = io.StringIO()
            with mock.patch.object(Path, "open", swapping_open):
                profile_env.follow_log(Path(repo), "hybrid", "api", out=out, forever=False)
            self.assertTrue(swapped)
            self.assertEqual(out.getvalue(), profile_env.LOG_RESTART_MARKER + new_content.decode())

    def test_split_utf8_code_point_decodes_without_replacement(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"")
            text = self._drive_follow(repo, "api", [
                lambda: log.write_bytes(b"\xf0\x9f"),
                lambda: log.write_bytes(b"\xf0\x9f\x98\x80"),
            ])
            self.assertEqual(text, "\U0001F600")
            self.assertNotIn("\ufffd", text)

    def test_truly_invalid_bytes_keep_replace_behavior(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"")
            text = self._drive_follow(repo, "api", [
                lambda: log.write_bytes(b"\xff\n"),
            ])
            self.assertEqual(text, "\ufffd\n")

    def test_exactly_one_marker_per_cutover(self) -> None:
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"generation-one-bytes")

            def replace_with(content: bytes):
                def mutate() -> None:
                    staged = log.with_name("api.log.staged")
                    staged.write_bytes(content)
                    os.replace(staged, log)
                return mutate

            marker = profile_env.LOG_RESTART_MARKER
            text = self._drive_follow(repo, "api", [
                replace_with(b"second-generation!!"),
                lambda: None,
                lambda: None,
                replace_with(b"third-generation!!!"),
                lambda: None,
            ])
            self.assertEqual(text.count(marker), 2)
            self.assertEqual(
                text,
                marker + "second-generation!!" + marker + "third-generation!!!",
            )

    def test_same_inode_truncate_and_fast_regrow_documents_detection_limit(self) -> None:
        """Expose the variant size/inode tracking cannot distinguish.

        An in-place truncate followed by a fast append that regrows past the
        saved offset, all under the same inode between two polls, looks like
        a plain append.  This needs an explicit generation/cutover signal;
        Effigy quarantines under a new inode, so the identity rule above
        covers the selected cutover and this test pins the boundary.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            log = self._process_log(repo)
            log.write_bytes(b"0123456789ABCDEF")
            regrown = b"NEW-CONTENT-REGROWN!"
            self.assertGreater(len(regrown), 16)

            def truncate_and_regrow() -> None:
                with log.open("r+b") as handle:
                    handle.seek(0)
                    handle.truncate(0)
                    handle.write(regrown)

            text = self._drive_follow(repo, "api", [truncate_and_regrow])
            self.assertNotIn(profile_env.LOG_RESTART_MARKER, text)
            self.assertEqual(text, regrown[16:].decode())


if __name__ == "__main__":
    unittest.main()
