#!/usr/bin/env python3
"""Hermetic tests for profile_env.py. No Effigy, containers or network."""

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


if __name__ == "__main__":
    unittest.main()
