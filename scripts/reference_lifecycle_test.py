"""Hermetic survivor controls: a stable supervisor cannot hide a recycled child."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "reference_runtime", Path(__file__).with_name("qualify-reference-runtime.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

optin_spec = importlib.util.spec_from_file_location(
    "reference_optin", Path(__file__).with_name("qualify-reference-optin.py"))
optin = importlib.util.module_from_spec(optin_spec)
assert optin_spec and optin_spec.loader
optin_spec.loader.exec_module(optin)
reference = runtime.REFERENCE


class SurvivorTests(unittest.TestCase):
    def setUp(self):
        self.before = {
            "owner": "second|hybrid|effigy|admin", "runtime_generation": "runtime",
            "generation": "old", "address": "127.0.0.1:12345", "status": "ready",
            "route_domain": "admin.fixture.test", "supervisor_pid": 100,
            "supervisor_start_identity": {"start_seconds": 1}, "child_pid": 101,
            "child_start_identity": {"start_seconds": 2},
        }

    def check(self, after):
        with patch.object(runtime.ssl, "create_default_context"), \
             patch.object(runtime.REFERENCE, "managed_listener_state", return_value=(None, after)), \
             patch.object(runtime.REFERENCE, "private_gateway_status", return_value={"routes": [
                 {"domain": after["route_domain"], "target": after["address"]}]}), \
             patch.object(runtime, "address_accepts_connection", return_value=True), \
             patch.object(runtime.REFERENCE, "gateway_request", return_value=(200, {}, b"")):
            return runtime.assert_foreign_instances_live(
                [(Path("/private/second"), {"admin": self.before})],
                Path("/private/gateway"), 8443, "interruption precondition")

    def test_unchanged_control_passes(self):
        self.assertEqual(self.check(dict(self.before))[0]["listeners"][0]["generation"], "old")

    def test_same_supervisor_recycled_child_fails_with_exact_evidence(self):
        after = {**self.before, "generation": "new", "address": "127.0.0.1:12346",
                 "child_pid": 102, "child_start_identity": {"start_seconds": 3}}
        with self.assertRaises(runtime.ForeignListenerChanged) as caught:
            self.check(after)
        evidence = caught.exception.evidence
        self.assertEqual(evidence["before"]["supervisor_pid"], evidence["after"]["supervisor_pid"])
        self.assertIn("generation", evidence["changed_fields"])
        self.assertEqual(evidence["phase"], "interruption precondition")

    def test_each_identity_change_fails_without_rebaselining(self):
        for key in ("owner", "runtime_generation", "generation", "address", "supervisor_pid",
                    "supervisor_start_identity", "child_pid", "child_start_identity"):
            with self.subTest(key=key), self.assertRaises(runtime.ForeignListenerChanged):
                self.check({**self.before, key: None})


class EffectiveRouteTests(unittest.TestCase):
    def write_listener(self, checkout: Path, name: str, route_domain: str) -> None:
        directory = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy"
        directory.mkdir(parents=True)
        state = {
            "status": "ready",
            "generation": "generation-1",
            "address": "127.0.0.1:41001",
            "route_domain": route_domain,
            "public_url": f"https://{route_domain}:8443",
            "route_owner": {"address": "127.0.0.1:41001"},
        }
        (directory / f"{name}.listener.json").write_text(json.dumps(state), encoding="utf-8")
        (directory / f"{name}.generation-1.listener-report.json").write_text(
            json.dumps({
                "schema": "effigy.managed.host-listener-report.v1",
                "generation": "generation-1",
                "address": "127.0.0.1:41001",
            }),
            encoding="utf-8",
        )

    def test_profile_listener_state_keeps_effective_route_and_uses_inventory_for_declaration(self):
        effective = "api.acme-w22e141dd.test"
        with tempfile.TemporaryDirectory(prefix="underlay-effective-route-") as temporary:
            checkout = Path(temporary)
            self.write_listener(checkout, "api", effective)
            _, state = optin.listener_state(checkout, "api", {}, {"api.acme.test": effective})
        self.assertEqual(state["route_domain"], effective)
        self.assertEqual(state["declared_route_domain"], "api.acme.test")

    def test_runtime_listener_state_validates_effective_route_without_rewriting_it(self):
        effective = "api.acme-w22e141dd.test"
        with tempfile.TemporaryDirectory(prefix="underlay-effective-route-") as temporary:
            checkout = Path(temporary)
            self.write_listener(checkout, "api", effective)
            _, state = reference.managed_listener_state(
                checkout, "api", expected_route_domain=effective
            )
            self.assertEqual(state["route_domain"], effective)
            with self.assertRaisesRegex(RuntimeError, "current effective route"):
                reference.managed_listener_state(
                    checkout, "api", expected_route_domain="api.acme.test"
                )


class ProcessAncestryTests(unittest.TestCase):
    def test_nested_effigy_task_chain_is_owned_by_the_recorded_adapter(self):
        parents = {200: 100, 300: 200, 400: 300}
        self.assertEqual(reference.process_ancestry_chain(400, 200, parents), [400, 300, 200])

    def test_missing_owner_or_cycle_fails_closed(self):
        self.assertIsNone(reference.process_ancestry_chain(400, 100, {400: 300, 300: 200}))
        self.assertIsNone(reference.process_ancestry_chain(400, 100, {400: 300, 300: 400}))


if __name__ == "__main__":
    unittest.main()
