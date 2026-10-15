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


def report(scope: str = "") -> dict:
    """Shape of `effigy container hybrid hosts --json` for a scoped checkout."""
    apex = f"acme{scope}.test"
    return {
        "cookie_domain": f"s3.{apex}",
        "routes": [
            route("http", "s3.acme.test", f"s3.{apex}", "minio"),
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
        env = profile_env.app_environment(report(), DECLARED, "acme")
        self.assertEqual(env["PUBLIC_HOST"], "api.acme.test")
        self.assertEqual(env["PUBLIC_PORT"], "443")
        self.assertEqual(env["CORS_ORIGINS"], "https://acme.test,https://admin.acme.test")
        self.assertEqual(env["COOKIE_DOMAIN"], ".acme.test")
        self.assertEqual(env["DATABASE_URL"], "postgres://postgres:secret@postgres.s3.acme.test:5432/acme")
        self.assertEqual(env["SMTP_HOST"], "smtp.s3.acme.test")
        self.assertEqual(env["EFFIGY_PROFILE_S3_PUBLIC_URL"], "https://s3.acme.test")

    def test_worktree_uses_effective_names_everywhere(self) -> None:
        env = profile_env.app_environment(report("-w1234abcd"), DECLARED, "acme")
        self.assertEqual(env["PUBLIC_HOST"], "api.acme-w1234abcd.test")
        self.assertEqual(env["COOKIE_DOMAIN"], ".acme-w1234abcd.test")
        self.assertIn("@postgres.s3.acme-w1234abcd.test:5432/", env["DATABASE_URL"])
        for value in env.values():
            self.assertNotIn("//acme.test", value)

    def test_nonstandard_gateway_port_reaches_public_urls(self) -> None:
        moved = report()
        for entry in moved["routes"]:
            if entry["kind"] == "http":
                entry["origin"] += ":8443"
        env = profile_env.app_environment(moved, DECLARED, "acme")
        self.assertEqual(env["PUBLIC_PORT"], "8443")
        self.assertEqual(env["EFFIGY_PROFILE_GATEWAY_HTTPS_PORT"], "8443")

    def test_missing_route_or_alias_refuses(self) -> None:
        without_admin = report()
        without_admin["routes"] = [r for r in without_admin["routes"] if r["declared"] != "admin.acme.test"]
        with self.assertRaisesRegex(profile_env.ProfileError, "admin"):
            profile_env.app_environment(without_admin, DECLARED, "acme")
        without_postgres = report()
        without_postgres["routes"] = [r for r in without_postgres["routes"] if r["service"] != "postgres"]
        with self.assertRaisesRegex(profile_env.ProfileError, "postgres"):
            profile_env.app_environment(without_postgres, DECLARED, "acme")

    def test_custom_front_label_still_finds_apex(self) -> None:
        self.assertEqual(profile_env.shared_apex(["api.acme.test", "www.acme.test", "admin.acme.test"]), "acme.test")
        with self.assertRaises(profile_env.ProfileError):
            profile_env.shared_apex(["api.acme.test", "admin.other.dev"])


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


if __name__ == "__main__":
    unittest.main()
