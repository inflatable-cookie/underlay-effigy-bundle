#!/usr/bin/env python3.11
"""Render DNS base domains and inspect Effigy's read-only host maps."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from bootstrap_sources_test import Fixture, envelope


HOST = "checkout.example.test"
ROUTE_INPUTS = {
    "host": HOST,
    "workspace_subdir": "fixture",
    "databases": ["fixture"],
    "routes.front": "frontdoor",
    "routes.s3": "objects",
}


class DnsBaseDomainTest(unittest.TestCase):
    def fixture(self, *, profiles: bool) -> tuple[Path, Fixture]:
        root = Path(tempfile.mkdtemp(prefix="dns-base-domain-fixture-"))
        self.addCleanup(shutil.rmtree, root, True)
        return root, Fixture(root, inputs={**ROUTE_INPUTS, "profiles.enabled": profiles})

    def host_report(self, fx: Fixture, container: str) -> dict:
        payload = envelope(
            ["--repo", str(fx.consumer), "container", container, "hosts"],
            fx.consumer,
        )
        self.assertEqual(payload["_exit"], 0, payload.get("error"))
        self.assertTrue(payload.get("ok"), payload.get("error"))
        return payload["result"]

    def assert_host_domains(self, report: dict, domain: str) -> None:
        self.assertEqual(report["base_domain"], {"declared": domain, "effective": domain})
        self.assertEqual(report["cookie_domain"], domain)
        self.assertEqual(report["relying_party_id"], domain)

        tcp_routes = [route for route in report["routes"] if route["kind"] == "tcp"]
        aliases = {route["service"]: route["declared"] for route in tcp_routes}
        self.assertEqual(aliases.get("postgres"), f"postgres.{domain}")
        self.assertEqual(aliases.get("mailpit"), f"smtp.{domain}")

    def test_main_and_profiles_use_the_checkout_or_profile_domain(self) -> None:
        _, fx = self.fixture(profiles=True)
        manifest = fx.effective()
        expected = {
            "stack": HOST,
            "hybrid": HOST,
            "hybrid-release": HOST,
            "test": f"test.{HOST}",
        }

        # Read the installed Effigy's actual nonmutating report, including its
        # derived cookie, relying-party and TCP alias fields.
        reports = {name: self.host_report(fx, name) for name in expected}
        for name, domain in expected.items():
            with self.subTest(container=name):
                self.assert_host_domains(reports[name], domain)

        for name, domain in expected.items():
            with self.subTest(rendered_container=name):
                dns = manifest["containers"][name]["dns"]
                self.assertEqual(dns["base_domain"], domain)

        main_routes = manifest["containers"]["stack"]["dns"]["routes"]
        self.assertEqual(main_routes[0]["domain"], f"frontdoor.{HOST}")
        self.assertIn(f"objects.{HOST}", [route["domain"] for route in main_routes])
        for name, domain in (("hybrid", HOST), ("hybrid-release", HOST), ("test", f"test.{HOST}")):
            profile_routes = manifest["containers"][name]["dns"]["routes"]
            self.assertEqual(profile_routes[0]["domain"], f"objects.{domain}")

    def test_profiles_disabled_main_container_keeps_explicit_domain(self) -> None:
        _, fx = self.fixture(profiles=False)
        manifest = fx.effective()
        self.assertEqual(set(manifest["containers"]) - {"default", "stack"}, set())
        self.assertEqual(manifest["containers"]["stack"]["dns"]["base_domain"], HOST)
        self.assert_host_domains(self.host_report(fx, "stack"), HOST)


if __name__ == "__main__":
    unittest.main()
