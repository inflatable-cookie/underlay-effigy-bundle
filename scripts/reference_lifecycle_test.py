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


class ReferenceTaskCwdTests(unittest.TestCase):
    def checkout(self, parent: Path) -> Path:
        root = parent / "reference"
        catalog = root / "apps/acme-api"
        catalog.mkdir(parents=True)
        (root / "effigy.toml").write_text(
            '[bundle.dirs]\napi = "apps/acme-api"\n\n'
            '[bundle.catalogs]\napi = "acme-api"\n',
            encoding="utf-8",
        )
        (catalog / "effigy.toml").write_text(
            '[catalog]\nalias = "acme-api"\n\n'
            '[tasks]\napi = "cd {repo} && cargo run -p acme-api {args}"\n',
            encoding="utf-8",
        )
        return root

    def test_configured_catalog_task_resolves_exact_canonical_cwd(self):
        with tempfile.TemporaryDirectory(prefix="underlay-api-cwd-") as temporary:
            root = self.checkout(Path(temporary))
            contract = reference.configured_reference_api_task_cwd(root)
            self.assertEqual(contract["selector"], "acme-api/api")
            self.assertEqual(contract["task_run"], "cd {repo} && cargo run -p acme-api {args}")
            self.assertEqual(contract["expected_cwd"], str((root / "apps/acme-api").resolve()))

    def test_catalog_mapping_rejects_alias_task_or_sibling_escape(self):
        with tempfile.TemporaryDirectory(prefix="underlay-api-cwd-") as temporary:
            parent = Path(temporary)
            root = self.checkout(parent)
            nested = root / "apps/acme-api/effigy.toml"
            nested.write_text(
                '[catalog]\nalias = "other-api"\n\n'
                '[tasks]\napi = "cd {repo} && cargo run -p acme-api {args}"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "alias"):
                reference.configured_reference_api_task_cwd(root)

            nested.write_text(
                '[catalog]\nalias = "acme-api"\n\n'
                '[tasks]\napi = "cargo run -p acme-api"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "exact catalog cwd"):
                reference.configured_reference_api_task_cwd(root)

            sibling = parent / "sibling/apps/acme-api"
            sibling.mkdir(parents=True)
            (sibling / "effigy.toml").write_text(nested.read_text(encoding="utf-8"), encoding="utf-8")
            (root / "apps/acme-api").rename(root / "apps/acme-api-original")
            (root / "apps/acme-api").symlink_to(sibling, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "outside its canonical checkout"):
                reference.configured_reference_api_task_cwd(root)

    def test_observed_cwd_requires_one_exact_canonical_directory(self):
        with tempfile.TemporaryDirectory(prefix="underlay-api-cwd-") as temporary:
            parent = Path(temporary)
            root = self.checkout(parent)
            expected = (root / "apps/acme-api").resolve()
            alias = parent / "catalog-alias"
            alias.symlink_to(expected, target_is_directory=True)
            matched, observation = reference.process_cwd_matches([str(alias)], expected)
            self.assertTrue(matched)
            self.assertEqual(observation["canonical_path"], str(expected))

            adjacent = parent / "apps/acme-api-adjacent"
            adjacent.mkdir(parents=True)
            for paths in ([], [str(expected), str(expected)]):
                with self.subTest(paths=paths):
                    matched, observation = reference.process_cwd_matches(paths, expected)
                    self.assertFalse(matched)
                    self.assertIsNotNone(observation["error"])
            matched, observation = reference.process_cwd_matches([str(adjacent)], expected)
            self.assertFalse(matched)
            self.assertEqual(observation["canonical_path"], str(adjacent.resolve()))

    def test_observed_api_executable_requires_exact_canonical_binary_and_hash(self):
        with tempfile.TemporaryDirectory(prefix="underlay-api-binary-") as temporary:
            parent = Path(temporary)
            expected = parent / "private-build/acme-api"
            expected.parent.mkdir()
            expected.write_bytes(b"qualified private API binary")
            expected_hash = optin._sha256_bytes(expected.read_bytes())
            alias = parent / "private-build-alias"
            alias.symlink_to(expected)
            matched, evidence = reference.process_executable_matches(
                [str(alias)], expected, expected_hash)
            self.assertTrue(matched)
            self.assertEqual(evidence["canonical_path"], str(expected.resolve()))

            # macOS lsof's `txt` inventory includes dyld and mapped files as
            # well as the executable. The exact expected binary must occur
            # once; unrelated text mappings do not make its identity ambiguous.
            matched, evidence = reference.process_executable_matches(
                [str(expected), "/usr/lib/dyld", "/usr/lib/libSystem.B.dylib"],
                expected, expected_hash)
            self.assertTrue(matched)
            self.assertEqual(evidence["matching_path_count"], 1)

            adjacent = parent / "adjacent/acme-api"
            adjacent.parent.mkdir()
            adjacent.write_bytes(expected.read_bytes())
            matched, evidence = reference.process_executable_matches(
                [str(adjacent)], expected, expected_hash)
            self.assertFalse(matched)
            self.assertEqual(evidence["expected_sha256"], expected_hash)
            for paths in ([], [str(expected), str(expected)]):
                with self.subTest(paths=paths):
                    matched, evidence = reference.process_executable_matches(
                        paths, expected, expected_hash)
                    self.assertFalse(matched)
                    self.assertIsNotNone(evidence["error"])

            matched, _ = reference.process_executable_matches(
                [str(expected)], expected, "0" * 64)
            self.assertFalse(matched)


class DiagnosticRecipeMatchTests(unittest.TestCase):
    def test_only_diagnostics_can_differ_from_retained_success_recipe(self):
        import subprocess
        for relative in ("scripts/dev/profile_launcher.py", "scripts/dev/managed-vite-listener.mjs"):
            with self.subTest(path=relative):
                current = (optin.ROOT / relative).read_text()
                baseline = subprocess.check_output(
                    ["git", "-C", str(optin.ROOT), "show", f"{optin.RETAINED_LIFECYCLE_HEAD}:{relative}"], text=True)
                self.assertTrue(optin.diagnostic_only_recipe_matches(relative, current, baseline))
                changed = current.replace('timeout: 300_000', 'timeout: 900_000') if relative.endswith('.mjs') else current.replace('timeout: int = 180', 'timeout: int = 900')
                self.assertNotEqual(changed, current)
                self.assertFalse(optin.diagnostic_only_recipe_matches(relative, changed, baseline))


class ExclusiveSocketTests(unittest.TestCase):
    def test_exact_single_kernel_owner_passes(self):
        matched, rows = reference.exclusive_listener_socket(
            "p123\ncacme-api\nn127.0.0.1:5000\n", 123, "127.0.0.1:5000")
        self.assertTrue(matched)
        self.assertEqual(rows[0]["pid"], 123)

    def test_foreign_duplicate_wildcard_and_missing_owner_refuse(self):
        exact = "p123\ncacme-api\nn127.0.0.1:5000\n"
        for output in ("", exact + "p456\ncforeign\nn127.0.0.1:5000\n",
                       exact + "n127.0.0.1:5000\n", exact.replace("127.0.0.1", "*"),
                       exact.replace("p123", "p456"), exact.replace("cacme-api", "cforeign")):
            with self.subTest(output=output):
                self.assertFalse(reference.exclusive_listener_socket(output, 123, "127.0.0.1:5000")[0])


class ProfileOwnerHoldTests(unittest.TestCase):
    def state_path(self, checkout: Path, name: str = "api") -> Path:
        path = optin._profile_probe_state_path(checkout, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_missing_or_unknown_managed_owner_state_holds_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="underlay-owner-hold-") as temporary:
            checkout = Path(temporary)
            with self.assertRaisesRegex(optin.UncertainProfileOwnership, "omitted"):
                optin._profile_listener_snapshots(checkout, ("api",), {})

            path = self.state_path(checkout)
            path.write_text(json.dumps({"schema": "unknown", "status": "ready"}), encoding="utf-8")
            with self.assertRaisesRegex(optin.UncertainProfileOwnership, "schema is unknown"):
                optin._profile_listener_snapshots(checkout, ("api",), {})

    def test_in_progress_owner_state_is_not_treated_as_stopped_or_released(self):
        with tempfile.TemporaryDirectory(prefix="underlay-owner-hold-") as temporary:
            checkout = Path(temporary)
            path = self.state_path(checkout)
            path.write_text(json.dumps({
                "schema": "effigy.managed.host-listener-state.v1",
                "status": "starting", "generation": "generation-1",
                "route_owner": None,
            }), encoding="utf-8")
            with self.assertRaisesRegex(optin.UncertainProfileOwnership, "'starting'"):
                optin._profile_listener_snapshots(checkout, ("api",), {})

    def test_probe_fixture_cannot_edit_checkout_outside_fresh_root(self):
        with tempfile.TemporaryDirectory(prefix="underlay-owner-hold-") as temporary:
            parent = Path(temporary)
            fixture_root = parent / "fixture"
            fixture_root.mkdir()
            checkout = parent / "outside"
            checkout.mkdir()
            manifest = checkout / "effigy.toml"
            manifest.write_text('[bundle]\n', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "disposable Reference checkout"):
                optin._append_profile_lifecycle_probe(
                    checkout, "interrupted_probe", "interrupted.api.test",
                    "127.0.0.1:0", 503,
                    {"UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(fixture_root)},
                )
            self.assertEqual(manifest.read_text(encoding="utf-8"), "[bundle]\n")


if __name__ == "__main__":
    unittest.main()
