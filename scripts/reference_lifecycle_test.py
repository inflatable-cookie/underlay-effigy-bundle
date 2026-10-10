"""Hermetic survivor controls: a stable supervisor cannot hide a recycled child."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "reference_runtime", Path(__file__).with_name("qualify-reference-runtime.py"))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


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


if __name__ == "__main__":
    unittest.main()
