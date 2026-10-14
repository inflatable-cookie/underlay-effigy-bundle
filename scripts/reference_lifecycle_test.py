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


class ServiceLogBoundaryTests(unittest.TestCase):
    def test_no_unbounded_backend_fallback_when_api_log_is_missing(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory(prefix='underlay-log-boundary-') as temporary:
            diagnostics=Mock()
            with patch.object(optin.RUNTIME,'run',side_effect=AssertionError('backend effect forbidden')) as run:
                optin.capture_storage_service_logs(Path(temporary),{},diagnostics)
            run.assert_not_called()
            diagnostics.append.assert_any_call('service_log_unavailable',service='silo',reason='no_qualified_finite_log_surface')
            diagnostics.write_log.assert_not_called()


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
        for relative in ("scripts/dev/profile_launcher.py", "scripts/dev/managed-vite-listener.mjs", "scripts/dev/port_inventory.py"):
            with self.subTest(path=relative):
                current = (optin.ROOT / relative).read_text()
                baseline = subprocess.check_output(
                    ["git", "-C", str(optin.ROOT), "show", f"{optin.RETAINED_LIFECYCLE_HEAD}:{relative}"], text=True, stderr=subprocess.DEVNULL) if not relative.endswith("port_inventory.py") else ""
                self.assertEqual(optin.diagnostic_only_recipe_matches(relative, current, baseline), relative.endswith(".mjs"))
                changed = (current+'\n# changed shared inventory input\n') if relative.endswith('port_inventory.py') else current.replace('timeout: 300_000', 'timeout: 900_000') if relative.endswith('.mjs') else current.replace('timeout: int = 180', 'timeout: int = 900')
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


class FixtureExtensionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="underlay-probe-extension-")
        self.fixture = Path(self.temporary.name)
        self.checkout = self.fixture / "reference"
        self.checkout.mkdir()
        self.manifest = self.checkout / "effigy.toml"
        self.original = b'[manifest]\r\nminimum_effigy_version = "0.13.1"\r\n[bundle]\r\n'
        self.manifest.write_bytes(self.original)
        self.env = {"UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(self.fixture)}
        self.secret = "seeded-secret-no-output"
        self.before = [{"name": role, "env": {"secret": self.secret}, "run": "original"}
                       for role in ("api", "front", "admin")]

    def tearDown(self):
        self.temporary.cleanup()

    def append(self, name="interrupted_probe"):
        return optin._append_profile_lifecycle_probe(
            self.checkout, name, "probe.api.test", "127.0.0.1:0", 503, self.env)

    def test_both_injection_paths_preserve_values_order_and_original_bytes(self):
        for name in ("interrupted_probe", "collision_probe"):
            after = self.before + [{"name": name}]
            with patch.object(optin, "_profile_semantic_hosts", side_effect=[self.before, after]):
                original = self.append(name)
            self.assertEqual(original, self.original)
            self.assertIn(optin.PROFILE_HOST_PATH.encode(), self.manifest.read_bytes())
            self.manifest.write_bytes(original)
            self.assertEqual(self.manifest.read_bytes(), self.original)

    def test_existing_extension_paths_are_preserved_without_duplicate_target(self):
        for source in ('[manifest]\nextend = ["tasks.example.run"]\n',
                       "[manifest]\nextend = [\n 'tasks.example.run',\n]\n",
                       '[manifest]\nextend = ["containers.hybrid_services.host_processes"]\n'):
            updated = optin._fixture_array_extension(source)
            self.assertEqual(updated.count(optin.PROFILE_HOST_PATH), 1)
            if "tasks.example.run" in source:
                self.assertIn("tasks.example.run", updated)

    def test_invalid_extension_settings_refuse_without_manifest_change(self):
        for section in ('extend = "wrong"', 'extend = [1]',
                        'extend = ["x", "x"]', 'extend = []\noverride = ["x"]',
                        'extend = []\nextend = []'):
            original = ('[manifest]\n' + section + '\n[bundle]\n').encode()
            self.manifest.write_bytes(original)
            with patch.object(optin, "_profile_semantic_hosts", return_value=self.before), self.assertRaises(RuntimeError):
                self.append()
            self.assertEqual(self.manifest.read_bytes(), original)

    def test_unknown_duplicate_missing_and_changed_production_entries_restore(self):
        variants = (self.before[:2], self.before + [{"name": "interrupted_probe"}, {"name": "interrupted_probe"}],
                    self.before + [{"name": "unknown"}],
                    [{**self.before[0], "run": "changed"}] + self.before[1:] + [{"name": "interrupted_probe"}])
        for after in variants:
            with patch.object(optin, "_profile_semantic_hosts", side_effect=[self.before, after]), self.assertRaises(RuntimeError) as error:
                self.append()
            self.assertNotIn(self.secret, str(error.exception))
            self.assertEqual(self.manifest.read_bytes(), self.original)
        with patch.object(optin, "_profile_semantic_hosts", return_value=[]), self.assertRaises(RuntimeError):
            self.append()

    def test_inspection_exception_and_interruption_restore_original(self):
        for error in (RuntimeError(self.secret), KeyboardInterrupt()):
            with patch.object(optin, "_profile_semantic_hosts", side_effect=[self.before, error]), self.assertRaises(type(error)):
                self.append()
            self.assertEqual(self.manifest.read_bytes(), self.original)

    def test_typed_contract_refusal_never_emits_seeded_values(self):
        valid = {"schema": "effigy.config.v1", "ok": True, "selected_path": optin.PROFILE_HOST_PATH,
                 "selected_value": {"path": optin.PROFILE_HOST_PATH, "value": self.before}}
        variants = ({}, {**valid, "ok": False}, {**valid, "schema": self.secret},
                    {**valid, "selected_value": {"path": optin.PROFILE_HOST_PATH, "value": {"name": self.secret}}},
                    {**valid, "selected_value": {"path": optin.PROFILE_HOST_PATH, "value": [self.secret]}})
        for value in variants:
            with patch.object(optin, "effigy_json", return_value=value), self.assertRaises(RuntimeError) as caught:
                optin._profile_semantic_hosts(self.checkout, self.env)
            self.assertNotIn(self.secret, str(caught.exception))
        with patch.object(optin, "effigy_json", side_effect=ValueError(self.secret)), self.assertRaises(RuntimeError) as caught:
            optin._profile_semantic_hosts(self.checkout, self.env)
        self.assertNotIn(self.secret, str(caught.exception))

    def test_manifest_symlink_and_foreign_checkout_escape_refuse(self):
        other = self.fixture / "other.toml"
        other.write_bytes(self.original)
        self.manifest.unlink()
        self.manifest.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.append()
        self.assertEqual(other.read_bytes(), self.original)

    def test_both_callers_restore_bytes_even_when_owner_state_is_uncertain(self):
        from contextlib import ExitStack
        from unittest.mock import Mock
        def append(*args):
            self.manifest.write_bytes(b"extended")
            return self.original
        for kind in ("interruption", "collision"):
            process = Mock(pid=100, returncode=1)
            process.poll.return_value = 1
            process.communicate.return_value = (None, None)
            with ExitStack() as stack:
                for target, name, kwargs in (
                    (optin, "_capture_lifecycle_probe_domain", {"return_value": "probe.api.test"}),
                    (optin, "selector", {}), (optin, "_verify_stopped", {}),
                    (optin, "_verify_live", {}),
                    (optin, "_append_profile_lifecycle_probe", {"side_effect": append}),
                    (optin.subprocess, "Popen", {"return_value": process}),
                    (optin.RUNTIME, "run", {"return_value": Mock(returncode=1, stdout="", stderr="")}),
                ):
                    stack.enter_context(patch.object(target, name, **kwargs))
                with self.assertRaises(optin.UncertainProfileOwnership):
                    if kind == "interruption":
                        optin._run_interruptible_profile_start(
                            self.checkout, self.env, Mock(), [], self.fixture, 8443, {})
                    else:
                        optin._run_profile_collision(
                            self.checkout, self.checkout, {"api": {"address": "127.0.0.1:41001"}},
                            self.env, Mock(), {})
                self.assertEqual(self.manifest.read_bytes(), self.original)

    def test_actual_private_export_array_extension_and_restoration(self):
        import os, subprocess, hashlib, tarfile, io
        binary = os.environ.get("UNDERLAY_PROFILE_EFFIGY_BIN")
        reference_source = os.environ.get("UNDERLAY_REFERENCE_SOURCE")
        if not binary or not reference_source:
            self.skipTest("actual assembly requires explicit qualified binary and Reference source")
        self.assertEqual(hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                         "95b16dbf56f507f0593ca205694fc5e667d311eee7e67b4e1d3afc81ba724938")
        bundle = self.fixture / "bundle"
        bundle.mkdir()
        for source, destination, revision in ((optin.ROOT, bundle, "HEAD"),
                                              (Path(reference_source), self.checkout, "fa6a5e89ad83db460a5506b7fa3f915fa767d72a")):
            archive_bytes = subprocess.run(["git", "-C", str(source), "archive", revision],
                                           capture_output=True, check=True, timeout=30).stdout
            with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
                for member in archive.getmembers():
                    self.assertFalse(member.issym() or member.islnk() or member.name.startswith("/") or ".." in Path(member.name).parts)
                archive.extractall(destination)
        # Apply the existing bundle fixture inputs, never copy production listeners.
        original_text = self.manifest.read_text()
        import re
        original_text = re.sub(r'(?m)^base\s*=.*$', 'base = ' + json.dumps({"type": "path", "dir": str(bundle)}).replace(':', ' ='), original_text, count=1)
        original_text = original_text.replace('[bundle]\n', '[bundle]\nprofiles = { enabled = true, effigy_source = ' + json.dumps(os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"]) + ', effigy_binary = ' + json.dumps(binary) + ', test_task = "acme-api/test", test_timeout_secs = 900, silo_bucket = "acme-media" }\n')
        self.manifest.write_bytes(original_text.encode())
        home = self.fixture / "home"
        home.mkdir()
        self.env.update(os.environ, HOME=str(home), UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT=str(self.fixture))
        with patch.object(optin, "EFFIGY", binary):
            before = optin._profile_semantic_hosts(self.checkout, self.env)
            self.assertEqual([x["name"] for x in before], ["api", "front", "admin"])
            original = self.append()
            after = optin._profile_semantic_hosts(self.checkout, self.env)
            self.assertEqual(after[:3], before)
            self.assertEqual([x["name"] for x in after], ["api", "front", "admin", "interrupted_probe"])
            self.manifest.write_bytes(original)
            self.assertEqual(optin._profile_semantic_hosts(self.checkout, self.env), before)
        self.assertEqual(self.manifest.read_bytes(), original_text.encode())


class LifecycleIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="underlay-lifecycle-identity-")
        self.fixture = Path(self.temporary.name)
        self.checkout = self.fixture / "reference"
        self.checkout.mkdir()
        (self.checkout / "effigy.toml").write_text("original")
        self.env = {"UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(self.fixture)}
        self.roles = {"api": "api.acme.test", "front": "acme.test", "admin": "admin.acme.test"}
        self.mapping = {domain: domain.replace("acme.test", "acme-w1234abcd.test")
                        for domain in (*self.roles.values(), "s3.acme.test", "silo.acme.test", "dbgate.acme.test", "mailpit.acme.test")}
        self.hosts = {"routes": [{"declared": key, "effective": value} for key, value in self.mapping.items()]}
        self.states = {}
        directory = self.checkout / ".effigy/runtime/host-processes/hybrid_services/effigy"
        directory.mkdir(parents=True)
        for index, (role, declared) in enumerate(self.roles.items()):
            state = {"schema": "effigy.managed.host-listener-state.v1", "status": "ready", "generation": "a" * 32,
                     "address": f"127.0.0.1:{41001 + index}", "route_domain": self.mapping[declared],
                     "public_url": "https://" + self.mapping[declared], "owner": "fixture|hybrid_services|effigy|" + role}
            state["route_owner"] = {"address": state["address"]}
            self.states[role] = state
            (directory / f"{role}.listener.json").write_text(json.dumps(state))
            (directory / f"{role}.{'a' * 32}.listener-report.json").write_text(json.dumps({
                "schema": "effigy.managed.host-listener-report.v1", "generation": "a" * 32,
                "address": state["address"]}))
        self.directory = directory

    def tearDown(self):
        self.temporary.cleanup()

    def stop(self):
        for role, before in self.states.items():
            (self.directory / f"{role}.listener.json").write_text(json.dumps({**before, "status": "stopped", "route_owner": None}))

    def test_interruption_captures_live_identity_before_down_and_reuses_exact_cleanup_domain(self):
        from contextlib import ExitStack
        from unittest.mock import Mock
        order = []
        live = True
        probe = self.directory / "interrupted_probe.listener.json"
        def hosts(*args, **kwargs):
            self.assertTrue(live, "identity queried after down")
            order.append("hosts")
            return self.hosts
        def selector(checkout, name, env, **kwargs):
            nonlocal live
            order.append(name)
            live = name == "dev:hybrid"
            if not live: self.stop()
        def append(checkout, name, domain, *args):
            self.assertFalse(live)
            self.assertEqual(domain, "interrupted.api.acme-w1234abcd.test")
            order.append("append")
            return b"original"
        process = Mock(pid=100, returncode=130)
        process.poll.side_effect = [None, None, 130, 130]
        process.communicate.return_value = (None, None)
        def launch(*args, **kwargs):
            probe.write_text(json.dumps({"status": "starting", "child_pid": 101,
                "owner": "fixture|hybrid_services|effigy|interrupted_probe",
                "runtime_generation": "b" * 32, "generation": "c" * 32}))
            (probe.parent / ("interrupted_probe." + "c" * 32 + ".barrier.json")).write_text(json.dumps({
                "generation": "c" * 32, "pid": 101, "report_file": str(probe.parent / (
                    "interrupted_probe." + "c" * 32 + ".listener-report.json"))}))
            order.append("launch")
            return process
        def verify_stopped_records(checkout, snapshots, env, **kwargs):
            self.assertFalse(live)
            self.assertEqual(kwargs["extra_routes"], ("interrupted.api.acme-w1234abcd.test",))
            order.append("cleanup")
        with ExitStack() as stack:
            for target, name, kwargs in (
                (optin, "effigy_json", {"side_effect": hosts}),
                (optin, "_verify_live", {"return_value": None}),
                (optin, "_verify_stopped", {"side_effect": lambda *args: self.assertFalse(live)}),
                (optin, "selector", {"side_effect": selector}),
                (optin, "_append_profile_lifecycle_probe", {"side_effect": append}),
                (optin.subprocess, "Popen", {"side_effect": launch}),
                (optin.os, "getpgid", {"return_value": 100}),
                (optin.os, "killpg", {"return_value": None}),
                (optin, "_profile_listener_snapshots", {"return_value": {}}),
                (optin.pending_start_identity, "capture_starting", {"return_value": {
                    "generation": "c" * 32, "owner": "fixture|hybrid_services|effigy|interrupted_probe",
                    "runtime_generation": "b" * 32, "child": {"pgid": 101}}}),
                (optin.pending_start_identity, "group_members", {"return_value": [101]}),
                (optin.pending_start_identity, "cleared_terminal", {}),
                (optin, "_profile_probe_diagnostic", {"return_value": {"http_status": 503, "route": "not_reached", "ownership": "exclusive_owner_observed", "status": "failed", "route_owner_present": False}}),
                (optin, "_verify_profile_stopped_records", {"side_effect": verify_stopped_records}),
                (optin, "listener_state", {"wraps": optin.listener_state}),
            ):
                stack.enter_context(patch.object(target, name, **kwargs))
            # Recovery models the supported selector writing ready state again.
            original_selector = selector
            def recover_selector(checkout, name, env, **kwargs):
                original_selector(checkout, name, env, **kwargs)
                if name == "dev:hybrid":
                    for role, state in self.states.items():
                        (self.directory / f"{role}.listener.json").write_text(json.dumps(state))
            stack.enter_context(patch.object(optin, "selector", side_effect=recover_selector))
            optin._run_interruptible_profile_start(self.checkout, self.env, Mock(), [], self.fixture, 8443, self.states)
        self.assertLess(order.index("hosts"), order.index("dev:hybrid:down"))
        self.assertLess(order.index("append"), order.index("launch"))
        self.assertIn("cleanup", order)

    def test_completed_probe_refuses_before_launcher_signal(self):
        from unittest.mock import Mock
        probe = self.directory / "interrupted_probe.listener.json"
        probe.write_text(json.dumps({"status": "failed"}))
        process = Mock(pid=100)
        process.poll.return_value = None
        with patch.object(optin, "_capture_lifecycle_probe_domain", return_value="probe.fixture.test"), \
             patch.object(optin, "selector"), patch.object(optin, "_verify_stopped"), \
             patch.object(optin, "_append_profile_lifecycle_probe", return_value=b"original"), \
             patch.object(optin.subprocess, "Popen", return_value=process), \
             patch.object(optin.os, "getpgid", return_value=100), \
             patch.object(optin.os, "killpg") as signal, \
             self.assertRaises(optin.UncertainProfileOwnership):
            optin._run_interruptible_profile_start(self.checkout, self.env, Mock(), [], self.fixture, 8443, self.states)
        # Finally may terminate its own still-live launcher, but cannot credit SIGINT.
        self.assertTrue(all(call.args[1] != optin.signal.SIGINT for call in signal.call_args_list))
        self.assertEqual((self.checkout / "effigy.toml").read_bytes(), b"original")

    def test_missing_conflicting_or_foreign_identity_refuses_before_down(self):
        for mapping in ({"routes": []}, {"routes": self.hosts["routes"] + [{"declared": "api.acme.test", "effective": "api.foreign.test"}]}):
            with patch.object(optin, "effigy_json", return_value=mapping), patch.object(optin, "selector") as selector:
                with self.assertRaises(RuntimeError):
                    optin._run_interruptible_profile_start(self.checkout, self.env, None, [], self.fixture, 8443, self.states)
                selector.assert_not_called()
        with patch.object(optin, "route_domains", return_value={role: self.mapping[domain] for role, domain in self.roles.items()}), \
             patch.object(optin, "_verify_live", side_effect=RuntimeError("foreign ownership")), \
             patch.object(optin, "selector") as selector:
            with self.assertRaisesRegex(RuntimeError, "foreign ownership"):
                optin._run_interruptible_profile_start(self.checkout, self.env, None, [], self.fixture, 8443, self.states)
            selector.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "owned disposable checkout"):
            optin._capture_lifecycle_probe_domain(self.fixture, self.env, self.states, "interrupted")

    def test_stopped_ownerless_live_publication_still_rejected(self):
        self.stop()
        with patch.object(optin, "effigy_json", return_value=self.hosts):
            with self.assertRaisesRegex(RuntimeError, "owned and ready"):
                optin.route_domains(self.checkout, self.env)

    def test_completed_restart_reuse_binds_prior_packet_and_validation_source(self):
        evidence = self.fixture / "prior"
        evidence.mkdir(mode=0o700)
        (evidence / "diagnostics").mkdir(mode=0o700)
        head = "f744fed7f810ecdea60ced2de8adff4a48533525"
        rows = [{"event": "attempt_started", "effigy_source": "8ecd64b37963cd6832a2b6ffa528034c56828504",
                 "effigy_binary_sha256": "03d10d8e58601896949ff042eb1b179f8cebddcb176d95c48d5573494b4ab324"},
                {"event": "retained_acceptance_input_match"}, {"event": "api_restart_signal_sent"},
                {"event": "reference_auth_build_identity", "reference_source_commit": "source",
                 "patch_sha256": "patch", "cargo_lock_sha256": "lock", "compile_selector": "acme-api/check"}]
        journal = evidence / "diagnostics/storage-diagnostics.jsonl"
        journal.write_text("\n".join(json.dumps(row) for row in rows))
        (evidence / "result.json").write_text(json.dumps({"head": head, "exit": 1, "run": "fixture"}))
        (evidence / "diagnostics/interruption-precondition-counterexample.json").write_text(json.dumps({
            "bundle_head": head, "run": "fixture", "phase": "interruption_fixture_preparation_after_owned_down",
            "journal_sha256": optin._sha256_file(journal)}))
        (evidence / "selector.log").write_text("\n".join((
            "PASS owned API child restart, new endpoint report, route replacement, and dependent restarts",
            "PASS actual Reference API/front/admin listeners and CA-verified private HTTPS routes",
            "PASS actual Reference front/admin event.url and request.url use configured HTTPS origins",
            "PASS front/admin Vite HMR WebSockets upgraded with 101 through gateway port 12345")))
        for path in evidence.rglob("*"):
            if path.is_file(): path.chmod(0o600)
        result = optin.validate_retained_restart_inputs(evidence)
        self.assertNotIn("generation", result)
        self.assertNotIn("owner", result)
        with patch.object(optin, "_source_function_sha256", side_effect=["changed", "original"]):
            with self.assertRaisesRegex(RuntimeError, "validation code changed"):
                optin.validate_retained_restart_inputs(evidence)
        journal.write_text(journal.read_text() + "\n{}")
        with self.assertRaisesRegex(RuntimeError, "bind the completed"):
            optin.validate_retained_restart_inputs(evidence)


class ListenerSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="underlay-listener-snapshot-")
        self.root = Path(self.temporary.name)
        self.checkout = self.root / "fixture"
        self.checkout.mkdir()
        diagnostics = self.root / "diagnostics"
        diagnostics.mkdir(mode=0o700)
        self.journal = optin.StorageDiagnosticJournal(diagnostics / "storage-diagnostics.jsonl", self.checkout)
        self.snapshots = optin.listener_snapshot
        self.snapshots.configure(self.journal.append)
        self.directory = self.checkout / ".effigy/runtime/host-processes/hybrid_services/effigy"
        self.directory.mkdir(parents=True)
        self.state_path = self.directory / "front.listener.json"
        self.secret = "seeded_password_token_presigned_SECRET"
        self.state = {"status": "ready", "generation": "a" * 32, "runtime_generation": "b" * 32,
                      "address": "127.0.0.1:41001", "route_domain": "acme.test",
                      "public_url": "https://acme.test:8443",
                      "route_owner": {"address": "127.0.0.1:41001", "credentials": self.secret},
                      "diagnostic": {"report": "accepted", "ownership": "exclusive_owner_observed",
                                     "http_probe": "ready", "http_status": 200, "route": "not_reached"},
                      "env": self.secret}
        self.write()

    def tearDown(self):
        self.snapshots.configure(None)
        self.journal.close()
        self.temporary.cleanup()

    def write(self):
        self.state_path.write_text(json.dumps(self.state))
        self.report_path = self.directory / f"front.{self.state['generation']}.listener-report.json"
        self.report_path.write_text(json.dumps({"schema": "effigy.managed.host-listener-report.v1",
                                              "generation": self.state["generation"],
                                              "address": self.state["address"], "body": self.secret}))

    def rows(self):
        text = self.journal.path.read_text()
        self.assertNotIn(self.secret, text)
        return [json.loads(line) for line in text.splitlines()]

    def validate(self, helper):
        if helper == "managed_listener_state":
            return reference.managed_listener_state(self.checkout, "front")
        return optin.listener_state(self.checkout, "front", {}, {"acme.test": "acme.test"})

    def test_unready_rejection_is_durable_before_raise_in_both_helpers(self):
        for helper in ("managed_listener_state", "listener_state"):
            self.state["status"] = "starting"
            self.state["route_owner"] = None
            self.write()
            with self.assertRaisesRegex(RuntimeError, "owned and ready"):
                self.validate(helper)
            rows = self.rows()
            self.assertEqual(rows[-2]["outcome"], "before_validation")
            self.assertEqual(rows[-1]["outcome"], "validation_rejected")
            self.assertEqual(rows[-2]["snapshot"], rows[-1]["snapshot"])
            self.assertEqual(rows[-1]["snapshot"]["state"]["status"], "starting")
            self.assertTrue(rows[-1]["snapshot"]["provenance"]["sha256"])

    def test_ready_then_unready_retains_generations_sequence_and_original_bytes(self):
        self.snapshots.old_states(self.checkout, {"front": self.state.copy()})
        self.validate("managed_listener_state")
        self.state.update(status="starting", generation="c" * 32, route_owner=None)
        self.write()
        with self.assertRaises(RuntimeError):
            self.validate("listener_state")
        self.state_path.unlink()
        rows = self.rows()
        states = [row for row in rows if row["snapshot"]["document"] == "state"]
        self.assertEqual([row["snapshot"]["state"]["generation"] for row in states],
                         ["a" * 32, "c" * 32, "c" * 32])
        self.assertEqual(states[-1]["snapshot"]["old"]["generation"], "a" * 32)
        self.assertEqual([row["observation_sequence"] for row in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(states[-1]["snapshot"]["provenance"], states[-2]["snapshot"]["provenance"])

    def test_unavailable_preserves_existing_state_owner_and_report_distinction(self):
        for helper in ("managed_listener_state", "listener_state"):
            self.state.update(status="unavailable", address=None, public_url=None)
            self.write()
            self.report_path.unlink()
            original = self.state_path.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "owned and ready"):
                self.validate(helper)
            row = self.rows()[-1]["snapshot"]
            self.assertEqual(row["state"]["status"], "unavailable")
            self.assertEqual(row["provenance"]["read"], "read")
            self.assertEqual(row["provenance"]["sha256"], __import__('hashlib').sha256(original).hexdigest())
            self.assertTrue(row["state"]["owner_present"])
            self.assertEqual(row["state"]["owner_target"], "127.0.0.1:41001")
            self.assertEqual(row["report"]["provenance"]["read"], "absent")
            self.assertEqual(self.state_path.read_bytes(), original)

    def test_unavailable_is_source_supported_without_granting_readiness(self):
        import os
        source = Path(os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"])
        text = (source / "src/runner/host_process.rs").read_text()
        self.assertIn('state.status = "unavailable".to_owned()', text)
        self.assertIn('unavailable.status = "unavailable".to_owned()', text)
        self.assertIn("unavailable", self.snapshots._STATUSES)
        for value in ("UNAVAILABLE", "unknown", None, {}, self.secret):
            self.assertEqual(self.snapshots._typed({"status": value})["status"], "unknown")

    def test_owned_exit_structural_capture_excludes_log_payload_and_bounds_tail(self):
        import os
        text = (Path(os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"]) / "src/runner/host_process.rs").read_text()
        self.assertIn("owned child exit observation refused: category={category}; owned_pid={pid}; status_code={:?}; stdout_bytes={}; stdout_sha256={}; stderr_bytes={}; stderr_sha256={}; utf8={}; tokens={tokens}; elapsed_ms={}", text)
        self.assertIn("owned child exit observation failed: {failure:?}; owned_pid={pid}; elapsed_ms={}", text)
        message = ("owned child exit observation refused: category=multiple_tokens; owned_pid=123; "
                   "status_code=Some(0); stdout_bytes=4; stdout_sha256=" + "a" * 64 +
                   "; stderr_bytes=0; stderr_sha256=" + "b" * 64 + "; utf8=true; tokens=2; elapsed_ms=4")
        projected = self.snapshots.owned_exit_projection(message)
        self.assertEqual(projected["tokens"], 2)
        self.assertEqual(projected["status_code"], 0)
        self.assertEqual(projected["category"], "multiple_tokens")
        for variant in ("Deadline", "Launch", "ReadFailure { stream: Stdout }",
                        "IncompleteOutput { stream: Stderr }",
                        "Overflow { stream: Stdout, limit_bytes: 64, retained_bytes: 65 }"):
            result = self.snapshots.owned_exit_projection(
                "owned child exit observation failed: " + variant + "; owned_pid=123; elapsed_ms=4")
            self.assertEqual(result["kind"], "capture_failed")
        self.assertEqual(self.snapshots.owned_exit_projection(message + self.secret)["kind"], "unclassified")
        log = self.directory / "front.log"
        log.write_text(self.secret * 3000 + "\n" + message + "\n")
        captured = []
        self.snapshots.capture_owned_exit_observations(self.checkout, lambda event, **fields: captured.append(fields))
        front = captured[1]
        self.assertTrue(front["tail_truncated"])
        self.assertLessEqual(front["tail_bytes"], 65536)
        self.assertEqual(front["observations"], [projected])
        self.assertEqual(front["authority"], "observation_only")
        self.assertNotIn(self.secret, json.dumps(captured))
        log.unlink()
        log.symlink_to(self.state_path)
        captured.clear()
        self.snapshots.capture_owned_exit_observations(self.checkout, lambda event, **fields: captured.append(fields))
        self.assertEqual(captured[1]["read"], "unavailable")

    def test_absent_malformed_permission_and_unknown_documents(self):
        for helper in ("managed_listener_state", "listener_state"):
            for kind in ("absent", "malformed", "permission_denied", "nonobject"):
                self.write()
                if kind == "absent":
                    self.state_path.unlink()
                elif kind == "malformed":
                    self.state_path.write_text(self.secret)
                elif kind == "nonobject":
                    self.state_path.write_text(json.dumps([self.secret]))
                from contextlib import nullcontext
                context = (patch.object(self.snapshots.os, "open", side_effect=PermissionError(self.secret))
                           if kind == "permission_denied" else nullcontext())
                with context, self.assertRaises(Exception):
                    self.validate(helper)
                self.assertEqual(self.rows()[-1]["snapshot"]["provenance"]["read"], kind)
        self.state.update(status=self.secret, diagnostic={"ownership": self.secret}, public_url="https://acme.test/?" + self.secret)
        self.write()
        with self.assertRaises(RuntimeError):
            self.validate("listener_state")
        self.assertEqual(self.rows()[-1]["snapshot"]["state"]["status"], "unknown")

    def test_report_failure_and_unknown_extras_preserve_gate(self):
        for helper in ("managed_listener_state", "listener_state"):
            for kind in ("absent", "malformed", "mismatch"):
                self.write()
                if kind == "absent":
                    self.report_path.unlink()
                elif kind == "malformed":
                    self.report_path.write_text(self.secret)
                else:
                    self.report_path.write_text(json.dumps({"schema": self.secret, "generation": "c" * 32,
                                                           "address": "127.0.0.1:41002"}))
                with self.assertRaises(Exception):
                    self.validate(helper)
                self.assertEqual(self.rows()[-1]["outcome"], "validation_rejected")

    def test_scope_extension_refuses_retained_function_reuse(self):
        import subprocess
        for filename, name in (("qualify-reference-optin.py", "listener_state"),
                               ("qualify-reference-profiles.py", "managed_listener_state")):
            path = "scripts/" + filename
            baseline = subprocess.run(["git", "show", f"{optin.RETAINED_LIFECYCLE_HEAD}:{path}"],
                                      check=True, capture_output=True, text=True, timeout=15).stdout
            current = Path(__file__).with_name(filename).read_text()
            digest = optin._source_function_sha256(baseline, name)
            current_digest = optin._source_function_sha256(current, name)
            if filename == "qualify-reference-optin.py":
                # The explicit disposable scope is a changed qualification input,
                # not diagnostic-only substitution or historical runtime credit.
                self.assertNotEqual(digest, current_digest)
            else:
                self.assertEqual(digest, current_digest)
            weakened = current.replace('state.get("status") != "ready"', 'state.get("status") != "starting"')
            self.assertNotEqual(current_digest, optin._source_function_sha256(weakened, name))

    def test_service_logs_are_unavailable_without_finite_backend_capture(self):
        with patch.object(optin.RUNTIME,'run',side_effect=AssertionError('backend effect forbidden')) as run:
            optin.capture_storage_service_logs(self.checkout,{},self.journal)
        run.assert_not_called()
        row=self.rows()[-1]
        self.assertEqual(row['event'],'service_log_unavailable')
        self.assertEqual(row['reason'],'no_qualified_finite_log_surface')



class PendingIdentityTests(unittest.TestCase):
    def setUp(self):
        self.module = optin.pending_start_identity
        self.boot = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        self.start = {"platform": "macos", "start_seconds": 10, "start_microseconds": 123456}
        self.state = {"schema": "effigy.managed.host-listener-state.v1", "status": "starting",
            "owner": "fixture|hybrid_services|effigy|interrupted_probe", "runtime_generation": "a" * 32,
            "generation": "b" * 32, "route_domain": "interrupted.api.fixture.test",
            "supervisor_pid": 100, "supervisor_boot_identity": self.boot,
            "supervisor_start_identity": self.start, "child_pid": 101,
            "child_boot_identity": self.boot, "child_start_identity": self.start}
    def live(self, pid):
        return {"pid": pid, "ppid": 100 if pid == 101 else 1, "pgid": pid,
                "uid": __import__("os").geteuid(), "boot_identity": self.boot, "start_identity": self.start}
    def capture(self, state=None):
        with patch.object(self.module, "kernel_identity", side_effect=self.live), \
             patch.object(self.module, "group_members", return_value=[101]):
            return self.module.capture_starting(state or self.state, self.state["owner"],
                self.state["runtime_generation"], self.state["route_domain"])
    def test_pending_receipt_retains_microseconds_and_group(self):
        receipt = self.capture()
        self.assertEqual(receipt["child"]["start_identity"]["start_microseconds"], 123456)
        self.assertEqual(receipt["members"][0]["pid"], 101)
    def test_completed_or_published_or_foreign_refuses(self):
        for key, value in (("status", "failed"), ("status", "ready"), ("owner", "foreign"),
                           ("runtime_generation", "unknown"), ("route_domain", "foreign.test"),
                           ("address", "127.0.0.1:1"), ("public_url", "https://foreign.test"),
                           ("route_owner", {}), ("listener_pid", 102)):
            with self.subTest(key=key), self.assertRaises(self.module.IdentityUnknown):
                self.capture({**self.state, key: value})
    def test_missing_microseconds_boot_group_or_reused_identity_refuses(self):
        for key, value in (("child_boot_identity", None), ("child_pid", None),
                           ("child_start_identity", {"platform": "macos", "start_seconds": 10}),
                           ("supervisor_start_identity", {**self.start, "start_microseconds": 123457})):
            with self.subTest(key=key), self.assertRaises(self.module.IdentityUnknown):
                self.capture({**self.state, key: value})
        for change in ({"pgid": 99}, {"ppid": 99}, {"boot_identity": "foreign"}):
            with patch.object(self.module, "kernel_identity", side_effect=lambda pid: {**self.live(pid), **change}), \
                 self.assertRaises(self.module.IdentityUnknown):
                self.module.capture_starting(self.state, self.state["owner"], "a" * 32, self.state["route_domain"])
    def test_cleared_failed_or_stopped_requires_independent_absence(self):
        receipt = self.capture()
        terminal = {**self.state, "child_pid": None, "child_boot_identity": None, "child_start_identity": None}
        for status in ("failed", "stopped"):
            with patch.object(self.module, "kernel_identity", return_value=None), \
                 patch.object(self.module, "boot_identity", return_value=self.boot), \
                 patch.object(self.module, "group_members", return_value=[]):
                self.module.cleared_terminal({**terminal, "status": status}, receipt)
            for key, value in (("child_pid", 101), ("route_owner", {}), ("address", "127.0.0.1:1"),
                               ("generation", "c" * 32), ("internal_url", "http://127.0.0.1:1")):
                with self.assertRaises(self.module.IdentityUnknown):
                    self.module.cleared_terminal({**terminal, "status": status, key: value}, receipt)
        for live, members in ((self.live(101), []), (None, [102])):
            with patch.object(self.module, "kernel_identity", return_value=live), \
                 patch.object(self.module, "boot_identity", return_value=self.boot), \
                 patch.object(self.module, "group_members", return_value=members), \
                 self.assertRaises(self.module.IdentityUnknown):
                self.module.cleared_terminal({**terminal, "status": "failed"}, receipt)
    def test_profile_absence_does_not_accept_seconds_only_or_reused_pid(self):
        snapshot = {"child_pid": 101, "child_boot_identity": self.boot,
                    "child_start_identity": self.start}
        with patch.object(self.module, "boot_identity", return_value=self.boot), \
             patch.object(self.module, "kernel_identity", return_value=None), \
             patch.object(self.module, "group_members", return_value=[]):
            optin._assert_profile_processes_absent({"api": snapshot})
            with self.assertRaises(optin.UncertainProfileOwnership):
                optin._assert_profile_processes_absent({"api": {**snapshot,
                    "child_start_identity": {"platform": "macos", "start_seconds": 10}}})
        with patch.object(self.module, "boot_identity", return_value=self.boot), \
             patch.object(self.module, "kernel_identity", return_value=self.live(101)), \
             self.assertRaises(optin.UncertainProfileOwnership):
            optin._assert_profile_processes_absent({"api": snapshot})

    def test_native_identity_surface_before_services(self):
        import os, sys
        if sys.platform != "darwin": self.skipTest("macOS opt-in only")
        identity = self.module.kernel_identity(os.getpid())
        self.assertEqual(identity["pid"], os.getpid())
        self.assertEqual(identity["pgid"], os.getpgid(os.getpid()))
        self.assertIn("start_microseconds", identity["start_identity"])


class PendingBarrierTests(unittest.TestCase):
    def test_confinement_generation_timeout_and_cleanup(self):
        import os
        from unittest.mock import Mock
        module = optin.load_module("pending_probe_test", Path(__file__).parent / "qualification/managed-listener-probe.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / ".effigy/runtime/host-processes/hybrid_services/effigy"
            parent.mkdir(parents=True)
            generation = "a" * 32
            report = parent / f"interrupted_probe.{generation}.listener-report.json"
            env = {"EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE": str(report),
                   "EFFIGY_MANAGED_HOST_LISTENER_GENERATION": generation}
            for stopped in (True, False):
                event = Mock()
                event.wait.return_value = stopped
                with patch.dict(os.environ, env), patch.object(module.Path, "cwd", return_value=root):
                    self.assertEqual(module.pending_barrier(event), 0 if stopped else 1)
                event.wait.assert_called_once_with(45)
                self.assertFalse(list(parent.glob("*.barrier.json")))
                self.assertFalse(report.exists())
            event = Mock()
            event.wait.side_effect = RuntimeError("injected")
            with patch.dict(os.environ, env), patch.object(module.Path, "cwd", return_value=root), self.assertRaises(RuntimeError):
                module.pending_barrier(event)
            self.assertFalse(list(parent.glob("*.barrier.json")))
            for bad in ("../escape", "b" * 32):
                with patch.dict(os.environ, {**env, "EFFIGY_MANAGED_HOST_LISTENER_GENERATION": bad}), \
                     patch.object(module.Path, "cwd", return_value=root), self.assertRaises(RuntimeError):
                    module.pending_barrier(Mock())


class TransitionCollectorTests(unittest.TestCase):
    def setUp(self):
        import transition_snapshot as transitions
        self.t = transitions
        self.temp = tempfile.TemporaryDirectory(prefix="underlay-transitions-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.checkout = self.root / "main"
        self.directory = self.checkout / ".effigy/runtime/host-processes/hybrid_services/effigy"
        self.directory.mkdir(parents=True)
        self.path = self.directory / "admin.transitions.jsonl"
        self.events = []
        transitions.configure(lambda event, **kw: self.events.append((event, kw)), self.root)
        self.addCleanup(lambda: transitions.configure(None, self.root))
        self.owner = "main|hybrid_services|effigy|admin"
        self.proc = {"pid": 123, "boot_identity": "12345678-1234-1234-1234-123456789abc",
                     "start_identity": {"platform": "macos", "start_seconds": 1234, "start_microseconds": 567}}
        self.record = {"schema": "effigy.managed.host-transition-evidence.v2", "sequence": 1,
                       "event": "successor_launched", "owner": self.owner, "runtime_generation": "a"*32,
                       "supervisor": self.proc, "generation": "b"*32, "phase": "pre_publication",
                       "child": self.proc, "child_group": 123,
                       "assignments": {"EFFIGY_MANAGED_HOST_API_GENERATION": "c"*32,
                                       "EFFIGY_MANAGED_HOST_API_INTERNAL_URL": "http://127.0.0.1:12345",
                                       "EFFIGY_MANAGED_HOST_API_PUBLIC_URL": "https://api.acme.test:8443",
                                       "EFFIGY_MANAGED_HOST_API_STATE_FILE": str(self.directory / "api.listener.json")}}

    def collect(self, records=None, suffix=b""):
        if records is not None:
            self.path.write_bytes(b"".join(json.dumps(r).encode()+b"\n" for r in records)+suffix)
        return self.t.collect(self.checkout, "admin", self.owner, "before_cleanup")

    def test_actual_collector_retains_exact_assignments_and_precise_identities(self):
        result = self.collect([self.record])
        self.assertEqual(result["knowledge"], "bounded_complete_observation")
        self.assertEqual(result["records"][0]["assignments"], self.record["assignments"])
        self.assertEqual(result["records"][0]["child"], self.proc)
        self.assertEqual(result["authority"], "observation_only")
        actual_launch = {k: v for k, v in self.record.items() if k != 'phase'}
        actual_launch['assignments'] = {**actual_launch['assignments'], 'EFFIGY_MANAGED_HOST_API_PUBLIC_URL': 'https://api.acme.test'}
        self.assertEqual(self.collect([actual_launch])["knowledge"], "bounded_complete_observation")
        historic = {**self.record, "schema": "effigy.managed.host-transition-evidence.v1", "sequence": 2}
        self.assertEqual(len(self.collect([self.record, historic])["records"]), 2)

    def test_selected_dependency_predicate_and_tuple_are_retained_without_inference(self):
        unavailable = {**self.record, 'sequence': 2, 'event': 'dependency_unavailable', 'phase': 'published',
                       'observed_dependencies': [{'name': 'api', 'status': 'unavailable', 'tuple_status': 'unavailable', 'predicate': 'state_not_ready'}]}
        changed = {**self.record, 'sequence': 3, 'event': 'dependency_tuple_changed', 'phase': 'published',
                   'observed_dependencies': [{'name': 'api', 'status': 'observed', 'tuple_status': 'observed', 'runtime_generation': 'd'*32, 'generation': 'e'*32, 'address': '127.0.0.1:12345'}]}
        result = self.collect([self.record, unavailable, changed])
        self.assertEqual(result['knowledge'], 'bounded_complete_observation')
        self.assertEqual(result['records'][1]['observed_dependencies'], unavailable['observed_dependencies'])
        self.assertEqual(result['records'][2]['observed_dependencies'], changed['observed_dependencies'])

    def test_missing_gaps_regression_tail_retention_and_truncation_are_unknown(self):
        self.assertIn("missing", self.collect()["issues"])
        for rows, tail in [([{**self.record, "sequence": 2}], b""),
                           ([self.record, self.record], b""),
                           ([self.record, {**self.record, "sequence": 3}], b""),
                           ([self.record], b'{"SECRET"'),
                           ([{**self.record, "event": "retention_limit"}], b""),
                           ([], b"")]:
            with self.subTest(rows=rows, tail=tail):
                self.assertEqual(self.collect(rows, tail)["knowledge"], "unknown")
        self.path.write_bytes(b'x'*(self.t.MAX_BYTES+1))
        self.assertEqual(self.collect()["knowledge"], "unknown")

    def test_unknown_schema_owner_fields_and_seeded_sensitive_assignments_are_excluded(self):
        import copy
        bads = [{**self.record, "event": "dependency_tuple_changed"},
                {**self.record, "event": "dependency_unavailable", "observed_dependencies": [{'name': 'api', 'status': 'unavailable', 'tuple_status': 'absent', 'predicate': 'route_owner_missing'}]},
                {**self.record, "schema": "SEEDED_SCHEMA"}, {**self.record, "owner": "SEEDED_OWNER"},
                {**self.record, "error": "SEEDED_ERROR"},
                {**self.record, "assignments": {"PASSWORD": "SEEDED_PASSWORD"}},
                {**self.record, "assignments": {"EFFIGY_MANAGED_HOST_API_PUBLIC_URL": "https://api.acme.test:443/?token=SEEDED"}},
                {**self.record, "assignments": {"EFFIGY_MANAGED_HOST_API_STATE_FILE": "/SEEDED"}},
                {**self.record, "observed_dependencies": [{"name": "api", "status": "observed", "tuple_status": "unreadable"}]},
                {**self.record, "observed_dependencies": [{"name": "api", "status": "observed", "tuple_status": "observed"}]}]
        for bad in bads:
            result = self.collect([bad])
            self.assertEqual(result["knowledge"], "unknown")
            self.assertNotIn("SEEDED", json.dumps(result))
            self.assertEqual(result["records"], [])
        self.path.write_bytes(b'not-json SEEDED\n')
        self.assertNotIn("SEEDED", json.dumps(self.collect()))

    def test_no_follow_ancestor_escape_and_unreadable_are_unknown(self):
        self.path.symlink_to(self.directory / "api.listener.json")
        self.assertEqual(self.collect()["knowledge"], "unknown")
        self.path.unlink()
        import os
        os.mkfifo(self.path)
        self.assertEqual(self.collect()["knowledge"], "unknown")
        self.path.unlink()
        self.checkout.rename(self.root / "owned")
        self.checkout.symlink_to(self.root / "owned", target_is_directory=True)
        self.assertEqual(self.collect()["knowledge"], "unknown")
        with patch.object(self.t.os, "open", side_effect=PermissionError):
            self.assertIn("permission_denied", self.collect()["issues"])
        self.assertEqual(self.t.collect(self.root.parent, "admin", self.owner, "before_cleanup")["knowledge"], "unknown")

    def test_production_listener_collection_keeps_gate_rejection_and_association(self):
        self.collect([self.record])
        optin.listener_snapshot.configure(lambda event, **kw: self.events.append((event, kw)))
        self.addCleanup(lambda: optin.listener_snapshot.configure(None))
        path = self.directory / "admin.listener.json"
        path.write_text(json.dumps({"status": "starting", "owner": self.owner, "generation": "b"*32}))
        with self.assertRaises(RuntimeError):
            optin.listener_state(self.checkout, "admin", {}, {"admin.acme.test": "admin.acme.test"})
        self.assertTrue(any(e == "managed_transition_snapshot" for e, _ in self.events))
        self.assertTrue(any(e == "listener_probe_snapshot" and kw["outcome"] == "validation_rejected" for e, kw in self.events))


if __name__ == "__main__":
    unittest.main()
