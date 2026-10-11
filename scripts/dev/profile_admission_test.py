#!/usr/bin/env python3
"""Hermetic contract checks for profile admission and owned setup."""

from __future__ import annotations

import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import shutil
import importlib.util
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import profile_launcher as profiles  # noqa: E402


class ContextDiagnosticTests(unittest.TestCase):
    def tearDown(self):
        profiles._CONTEXT_ACTION = False
        profiles._context_mark("admission", "verify")

    def test_injected_status_failure_retains_phase_without_secret_message(self):
        profiles._CONTEXT_ACTION = True
        with patch.object(profiles, "_json_command", side_effect=profiles.ProfileError("SEEDED_PASSWORD /secret/key?token=SEEDED_TOKEN")):
            with self.assertRaises(profiles.ProfileError) as caught:
                profiles.profile_context(None, Path("/fixture"), {"EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": "/private"}, "hybrid_services")
        record = profiles.context_error_record(caught.exception)
        self.assertEqual(record["phase"], "service-status")
        self.assertEqual(record["operation"], "hybrid_services.status")
        self.assertNotIn("SEEDED", json.dumps(record))
        self.assertNotIn("/secret", json.dumps(record))

    def test_injected_gateway_and_port_failures_identify_suboperation(self):
        for phase, operation, target in [("gateway-status", "gateway.status", "_gateway_json"),
                                          ("service-port", "postgres", "_service_port")]:
            with self.subTest(phase=phase), patch.object(profiles, "_json_command", return_value={}), \
                 patch.object(profiles, "_compose_loopback_port_bindings", return_value=[]), \
                 patch.object(profiles, "_gateway_json", return_value={}), \
                 patch.object(profiles, "_gateway_https_port", return_value=8443), \
                 patch.object(profiles, target, side_effect=profiles.ProfileError("binding conflict SEEDED_CREDENTIAL")):
                with self.assertRaises(profiles.ProfileError) as caught:
                    profiles.profile_context(None, Path("/fixture"), {"EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": "/private"}, "hybrid_services")
                record = profiles.context_error_record(caught.exception)
                self.assertEqual((record["phase"], record["operation"]), (phase, operation))
                self.assertNotIn("SEEDED", json.dumps(record))

    def test_context_command_suppresses_raw_stderr_and_validates_record(self):
        profiles._CONTEXT_ACTION = True
        identity = profiles.BinaryIdentity("source", "/binary", "digest", 1, 2, 3, 4)
        with patch.object(profiles, "_run_process", return_value=subprocess.CompletedProcess([], 1, '{"ok":false,"error":{"message":"SEEDED_SECRET"}}', "SEEDED_STDERR")) as run:
            with self.assertRaises(profiles.ProfileError):
                profiles._json_command(identity, Path("/fixture"), {}, "container", "hybrid_services", "status")
            self.assertFalse(run.call_args.kwargs["emit_stderr"])
            self.assertFalse(run.call_args.kwargs["emit_stdout"])
        record = profiles.context_error_record(profiles.ProfileError("SEEDED"))
        self.assertEqual(profiles.validated_context_record({**record, "body": "SEEDED"}), record)
        self.assertIsNone(profiles.validated_context_record({**record, "message": "SEEDED"}))


class ProfileAdmissionTests(unittest.TestCase):
    def test_reviewed_source_pin_refuses_historical_capability(self):
        self.assertEqual(profiles.SUPPORTED_SOURCE, "6da2f94bcc1400f9165b954a5343bd0cb14267ac")
        self.assertEqual(profiles.SUPPORTED_BINARY_SHA256, "5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8")
        with tempfile.TemporaryDirectory(prefix="underlay-old-pin-") as temporary:
            source = Path(temporary).resolve()
            binary = source / "effigy"
            binary.write_bytes(b"historical")
            binary.chmod(0o700)
            with patch.object(profiles, "_git", side_effect=[str(source), "8ecd64b37963cd6832a2b6ffa528034c56828504"]), \
                 patch.object(profiles.subprocess, "run") as run, self.assertRaises(profiles.ProfileError):
                profiles.verify_binary(str(source), str(binary), system="Darwin", machine="arm64")
            run.assert_not_called()

    def _write_compose_ports(self, repo: Path, postgres_binding: str) -> dict:
        compose = repo / ".effigy/runtime/compose/.effigy-compose.generated.yml"
        compose.parent.mkdir(parents=True)
        compose.write_text(
            "services:\n"
            "  postgres:\n"
            "    ports:\n"
            f"    - {postgres_binding}\n",
            encoding="utf-8",
        )
        return {"compose_file": str(compose.relative_to(repo))}

    def test_service_port_resolves_loopback_compose_port_before_status_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({"services": [], "ports": []})
            self.assertEqual(profiles._service_port(status, "postgres", 5432, repo), 65432)

    def test_service_port_uses_compose_when_status_row_has_no_port_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({"services": [{"name": "postgres", "ports": []}], "ports": []})
            self.assertEqual(profiles._service_port(status, "postgres", 5432, repo), 65432)

    def test_service_port_confirms_live_mapping_against_compose(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({
                "services": [{"name": "postgres", "ports": ["127.0.0.1:65432->5432/tcp"]}],
                "ports": ["65432:5432"],
            })
            self.assertEqual(profiles._service_port(status, "postgres", 5432, repo), 65432)

    def test_explicit_live_loopback_service_mapping_survives_stale_compose_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({
                "services": [{"name": "postgres", "ports": ["127.0.0.1:65433->5432/tcp"]}],
                "ports": ["65433:5432"],
            })
            self.assertEqual(profiles._service_port(status, "postgres", 5432, repo), 65433)

    def test_explicit_live_loopback_mapping_must_match_status_allocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({
                "services": [{"name": "postgres", "ports": ["127.0.0.1:65433->5432/tcp"]}],
                "ports": ["65434:5432"],
            })
            with self.assertRaisesRegex(profiles.ProfileError, "conflicts with its status allocation"):
                profiles._service_port(status, "postgres", 5432, repo)

    def test_service_port_refuses_ambiguous_or_public_allocations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({"services": [], "ports": ["65432:5432", "65433:5432"]})
            with self.assertRaisesRegex(profiles.ProfileError, "unambiguous loopback"):
                profiles._service_port(status, "postgres", 5432, repo)

        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "0.0.0.0:65432:5432")
            status.update({"services": [], "ports": ["65432:5432"]})
            with self.assertRaisesRegex(profiles.ProfileError, "unambiguous loopback"):
                profiles._service_port(status, "postgres", 5432, repo)

    def test_service_port_rejects_public_live_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            status = self._write_compose_ports(repo, "127.0.0.1:65432:5432")
            status.update({
                "services": [{"name": "postgres", "ports": ["0.0.0.0:65432->5432/tcp"]}],
                "ports": ["65432:5432"],
            })
            with self.assertRaisesRegex(profiles.ProfileError, "non-loopback"):
                profiles._service_port(status, "postgres", 5432, repo)

    def test_json_command_removes_effigy_header_suppression(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        env = {"EFFIGY_INTERNAL_SUPPRESS_HEADER": "1", "PROFILE_FIXTURE": "kept"}
        response = unittest.mock.Mock(stdout=json.dumps({"ok": True, "result": {"ports": ["65432:5432"]}}))
        with patch.object(profiles, "_run_process", return_value=response) as run:
            result = profiles._json_command(identity, Path("/fixture"), env, "container", "hybrid_services", "status")
        self.assertEqual(result, {"ports": ["65432:5432"]})
        self.assertNotIn("EFFIGY_INTERNAL_SUPPRESS_HEADER", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["env"]["PROFILE_FIXTURE"], "kept")

    def test_profile_context_combines_service_routes_with_checkout_host_map(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        repo = Path("/fixture")
        names = {
            "api": "api.fixture.test",
            "front": "fixture.test",
            "admin": "admin.fixture.test",
            "s3": "s3.fixture.test",
            "dbgate": "dbgate.fixture.test",
            "mailpit": "mailpit.fixture.test",
            "silo": "silo.fixture.test",
        }
        env = {
            "EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": "/fixture/.effigy/runtime/dev-profiles/hybrid/gateway",
            "EFFIGY_PROFILE_CONTAINER_NAME": "hybrid_services",
            "EFFIGY_PROFILE_HOST_CONTAINER_NAME": "hybrid_services",
            **{f"EFFIGY_PROFILE_{name.upper()}_DECLARED": domain for name, domain in names.items()},
        }
        service_names = {"s3", "dbgate", "mailpit", "silo"}
        service_hosts = {"routes": [
            {"declared": names[name], "effective": names[name]}
            for name in service_names
        ]}
        checkout_hosts = {"routes": [
            {"declared": names[name], "effective": names[name]}
            for name in ("api", "front", "admin")
        ]}
        order: list[str] = []
        binding_snapshot = [("postgres", 65432, 5432)]

        def json_command(_identity, _repo, _env, *args):
            if args == ("container", "hybrid_services", "status"):
                order.append("status")
                return {"services": [], "ports": []}
            if args == ("container", "hybrid_services", "hosts"):
                order.append("service_hosts")
                return service_hosts
            if args == ("container", "hosts"):
                order.append("checkout_hosts")
                return checkout_hosts
            self.fail(f"unexpected Effigy JSON command: {args!r}")

        def compose_bindings(_repo, _status):
            order.append("compose_snapshot")
            return binding_snapshot

        def service_port(_status, _service, port, _repo, **kwargs):
            self.assertIs(kwargs["compose_bindings"], binding_snapshot)
            return port + 10000

        with patch.object(profiles, "_json_command", side_effect=json_command) as command, \
                patch.object(profiles, "_gateway_json", return_value={
                    "private": True, "running": True, "https_addr": "127.0.0.1:44321",
                }), \
                patch.object(profiles, "_compose_loopback_port_bindings", side_effect=compose_bindings), \
                patch.object(profiles, "_service_port", side_effect=service_port):
            context = profiles.profile_context(identity, repo, env, "hybrid_services")

        self.assertEqual(context["routes"], names)
        self.assertEqual(context["https_port"], 44321)
        self.assertEqual(order[:4], ["status", "compose_snapshot", "service_hosts", "checkout_hosts"])
        self.assertIn(unittest.mock.call(identity, repo, env, "container", "hosts"), command.call_args_list)

    def test_unsupported_platform_refuses_before_reading_paths(self) -> None:
        with self.assertRaisesRegex(profiles.ProfileError, "qualified only for macOS arm64"):
            profiles.verify_binary("/missing/source", "/missing/effigy", system="Linux", machine="x86_64")

    def test_unconfigured_identity_refuses(self) -> None:
        with self.assertRaisesRegex(profiles.ProfileError, "profiles.effigy_source"):
            profiles.verify_binary("", "")

    def test_qualified_identity_requires_clean_exact_checkout_and_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            binary = root / "effigy"
            binary.write_bytes(b"qualified fixture binary")
            binary.chmod(0o700)
            git_outputs = iter((str(source), profiles.SUPPORTED_SOURCE, ""))

            def git(_source: Path, *_args: str) -> str:
                return next(git_outputs)

            run = unittest.mock.Mock(return_value=unittest.mock.Mock(stdout=profiles.SUPPORTED_VERSION))
            with patch.object(profiles, "_git", side_effect=git), patch.object(profiles, "_hash_file", return_value=profiles.SUPPORTED_BINARY_SHA256), patch.object(profiles.subprocess, "run", run):
                identity = profiles.verify_binary(str(source), str(binary))
            self.assertEqual(identity.source, str(source))
            self.assertEqual(identity.binary, str(binary))
            self.assertEqual(identity.digest, profiles.SUPPORTED_BINARY_SHA256)
            self.assertTrue(stat.S_IMODE(binary.stat().st_mode) & stat.S_IXUSR)

    def test_old_unknown_or_wrong_hash_binary_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            binary = root / "effigy"
            binary.write_bytes(b"old or unknown build")
            binary.chmod(0o700)
            git_outputs = iter((str(source), profiles.SUPPORTED_SOURCE, ""))
            run = unittest.mock.Mock(return_value=unittest.mock.Mock(stdout=profiles.SUPPORTED_VERSION))
            with patch.object(profiles, "_git", side_effect=lambda *_args: next(git_outputs)), patch.object(profiles, "_hash_file", return_value="0" * 64), patch.object(profiles.subprocess, "run", run):
                with self.assertRaisesRegex(profiles.ProfileError, "SHA-256 is not the qualified"):
                    profiles.verify_binary(str(source), str(binary))

    def test_binary_change_after_admission_stops_before_spawn(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with patch.object(profiles, "verify_unchanged", side_effect=profiles.ProfileError("identity changed")), patch.object(profiles.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(profiles.ProfileError, "identity changed"):
                profiles._run_process(identity, [identity.binary, "tasks"], cwd=Path("."), env={}, timeout=1)
        spawn.assert_not_called()

    def test_nested_invocation_rejects_path_lookup(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with patch.object(profiles, "verify_unchanged"), patch.object(profiles.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(profiles.ProfileError, "not bound to the verified absolute binary"):
                profiles._run_process(identity, ["effigy", "tasks"], cwd=Path("."), env={}, timeout=1)
        spawn.assert_not_called()

    def test_refused_opt_in_has_no_profile_or_catalog_side_effect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            (repo / "effigy.toml").write_text("[bundle]\nname='fixture'\n", encoding="utf-8")
            env = {"UNDERLAY_PROFILE_EFFIGY_SOURCE": "/unqualified", "UNDERLAY_PROFILE_EFFIGY_BIN": "/unqualified/effigy"}
            with patch.dict(os.environ, env, clear=True), patch.object(profiles.platform, "system", return_value="Linux"), patch.object(profiles.platform, "machine", return_value="x86_64"):
                with self.assertRaisesRegex(profiles.ProfileError, "qualified only for macOS arm64"):
                    profiles.main(["start", "hybrid", "--repo", str(repo)])
            self.assertFalse((repo / ".effigy").exists())
            self.assertFalse((repo / "infra/dev/catalog/silo").exists())

    def test_silo_override_conflict_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            target = repo / "infra/dev/catalog/silo"
            target.mkdir(parents=True)
            original = b"operator-owned catalog fragment\n"
            (target / "service.toml").write_bytes(original)
            with self.assertRaisesRegex(profiles.ProfileError, "differs from the bundle-owned"):
                profiles._prepare_silo_override(repo)
            self.assertEqual((target / "service.toml").read_bytes(), original)

    def test_client_catalog_conflict_does_not_partially_install_server_catalog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            target = repo / "infra/dev/catalog/silo-mc"
            target.mkdir(parents=True)
            (target / "service.toml").write_text("operator-owned\n", encoding="utf-8")
            with self.assertRaisesRegex(profiles.ProfileError, "differs from the bundle-owned"):
                profiles._prepare_silo_override(repo)
            self.assertEqual((target / "service.toml").read_text(encoding="utf-8"), "operator-owned\n")
            self.assertFalse((repo / "infra/dev/catalog/silo").exists())

    def test_silo_bootstrap_uses_pinned_client_sidecar_and_actual_bucket(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary)
            env = {"EFFIGY_PROFILE_SILO_BUCKET": "acme-media"}
            context = {"routes": {"front": "front.fixture.test", "admin": "admin.fixture.test"},
                       "https_port": 443}
            with patch.object(profiles, "_run_process", return_value=None) as command:
                profiles._bootstrap_silo(identity, repo, env, "hybrid_services", context)
            self.assertEqual(command.call_count, 3)
            commands = [call.args[1] for call in command.call_args_list]
            stages = [args[args.index("--command") + 1] for args in commands]
            self.assertTrue(all("shell" in args and "silo_client" in args for args in commands))
            self.assertTrue(all("--json" not in args for args in commands))
            self.assertTrue(all(call.kwargs["emit_stderr"] is False for call in command.call_args_list))
            self.assertIn("http://silo:9000", stages[0])
            self.assertIn("mc mb local/acme-media", stages[1])
            self.assertIn("<AllowedOrigin>https://front.fixture.test</AllowedOrigin>", stages[2])
            self.assertIn("<AllowedOrigin>https://admin.fixture.test</AllowedOrigin>", stages[2])
            self.assertIn("mc cors set local/acme-media", stages[2])

    def test_private_state_root_is_confined_and_mode_0700(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            root = profiles._ensure_private_root(repo, "hybrid")
            self.assertEqual(root, repo / ".effigy/runtime/dev-profiles/hybrid/gateway")
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_private_state_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = (Path(temporary) / "repo")
            repo.mkdir()
            repo = repo.resolve()
            outside = Path(temporary) / "outside"
            outside.mkdir()
            outside = outside.resolve()
            (repo / ".effigy").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(profiles.ProfileError, "escapes the consumer checkout|contains a symlink"):
                profiles._ensure_private_root(repo, "hybrid")

    def test_managed_adapters_must_match_the_profile_container_pair(self) -> None:
        self.assertEqual(profiles.profile_for_containers("hybrid_services", "hybrid_services"), "hybrid")
        self.assertEqual(profiles.profile_for_containers("disposable_test", "disposable_test"), "disposable_test")
        for service, host in (("hybrid_services", "disposable_test"), ("hybrid", "hybrid_services")):
            with self.subTest(service=service, host=host), self.assertRaisesRegex(
                profiles.ProfileError, "unsupported managed profile containers"
            ):
                profiles.profile_for_containers(service, host)

    def test_private_gateway_commands_use_gateway_cli_without_repo_flag(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        outputs = (
            '{"ok":true,"result":{"running":false,"routes":[]}}',
            '{"ok":true,"result":{"schema":"effigy.command.v1",'
            '"result":{"running":false,"routes":[]}}}',
            '{"ok":true,"result":{"ok":true,"schema":"effigy.command.v1",'
            '"result":{"running":false,"routes":[]}}}',
        )
        for output in outputs:
            result = subprocess.CompletedProcess([identity.binary], 0, output, "")
            with self.subTest(output=output), patch.object(profiles, "_run_process", return_value=result) as run:
                status = profiles._gateway_json(
                    identity,
                    Path("/consumer"),
                    {"EFFIGY_INTERNAL_SUPPRESS_HEADER": "1"},
                    "status",
                    "--private-state-root",
                    "/consumer/.effigy/gateway",
                )
                self.assertEqual(status, {"running": False, "routes": []})
                self.assertEqual(
                    run.call_args.args[1],
                    [identity.binary, "--json", "gateway", "status", "--private-state-root", "/consumer/.effigy/gateway"],
                )
                self.assertNotIn("--repo", run.call_args.args[1])
                self.assertNotIn("EFFIGY_INTERNAL_SUPPRESS_HEADER", run.call_args.kwargs["env"])

    def test_gateway_start_waits_for_an_actual_private_https_address(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with patch.object(
            profiles,
            "_gateway_json",
            side_effect=[{}, {"private": True, "running": True, "https_addr": "127.0.0.1:43210"}],
        ) as gateway:
            profiles._gateway_start(identity, Path("/consumer"), {}, Path("/consumer/.effigy/gateway"))
        self.assertEqual([call.args[3] for call in gateway.call_args_list], ["setup-tls", "up"])
        with self.assertRaisesRegex(profiles.ProfileError, "HTTPS port is outside the TCP range.*127.0.0.1:0"):
            profiles._gateway_https_port({"private": True, "running": False, "https_addr": "127.0.0.1:0"})

    def test_unknown_listener_state_is_held_before_start(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            state_root = repo / ".effigy/runtime/host-processes/hybrid_services/effigy"
            state_root.mkdir(parents=True)
            (state_root / "api.listener.json").write_text(json.dumps({"generation": "unknown"}), encoding="utf-8")
            with patch.object(profiles, "_json_command", return_value={"services": []}):
                with self.assertRaisesRegex(profiles.ProfileError, "recorded host listener ownership"):
                    profiles._assert_stopped(identity, repo, {}, "hybrid_services")

    def test_listener_owner_key_uses_the_effigy_checkout_scope_identity(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = (Path(temporary) / "first").resolve()
            token = "2f4cb9b5af55e39a1def8ae92e19079b"
            scope_response = {
                "schema": "effigy.container.scope.v1",
                "ok": True,
                "checkout": str(repo),
                "scope": {"kind": "worktree", "token": token},
            }
            with patch.object(profiles, "_json_command", return_value=scope_response) as command:
                self.assertEqual(profiles._scope_owner_key(identity, repo, {}), token)
            command.assert_called_once_with(identity, repo, {}, "container", "scope")

            scope_response["checkout"] = str(repo.parent / "other")
            with patch.object(profiles, "_json_command", return_value=scope_response):
                with self.assertRaisesRegex(profiles.ProfileError, "does not match the admitted consumer checkout"):
                    profiles._scope_owner_key(identity, repo, {})

    def test_listener_owner_key_requires_a_full_scoped_generation_token(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        repo = Path("/fixture/worktree")
        for scope in (
            {"kind": "worktree", "token": "short"},
            {"kind": "ephemeral-clone", "token": None},
            {"kind": "unknown", "token": None},
            {"kind": "none", "token": "unexpected"},
        ):
            response = {
                "schema": "effigy.container.scope.v1",
                "ok": True,
                "checkout": str(repo.resolve()),
                "scope": scope,
            }
            with self.subTest(scope=scope), patch.object(profiles, "_json_command", return_value=response):
                with self.assertRaisesRegex(profiles.ProfileError, "invalid kind or generation token"):
                    profiles._scope_owner_key(identity, repo, {})

    def test_uncertain_listener_owner_is_preserved_after_down(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            repo = Path(temporary).resolve()
            state_root = repo / ".effigy/runtime/host-processes/hybrid_services/effigy"
            state_root.mkdir(parents=True)
            state_path = state_root / "api.listener.json"
            original = json.dumps({"status": "failed", "route_owner": {"address": "127.0.0.1:41234"}})
            state_path.write_text(original, encoding="utf-8")
            with patch.object(profiles, "_json_command", side_effect=[{}, {"services": []}]):
                with self.assertRaisesRegex(profiles.ProfileError, "managed host listeners remain uncertain"):
                    profiles._container_down(identity, repo, {}, "hybrid_services")
            self.assertEqual(state_path.read_text(encoding="utf-8"), original)

    def test_partial_profile_start_reconciles_only_its_combined_scope(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        repo = Path("/fixture")
        with patch.object(profiles, "_profile_root", return_value=Path("/private/gateway")), \
             patch.object(profiles, "_profile_env", return_value={}), \
             patch.object(profiles, "_prepare_silo_override"), \
             patch.object(profiles, "_json_command", return_value={"services": []}), \
             patch.object(profiles, "_private_gateway_status", return_value={"running": False, "routes": []}), \
             patch.object(profiles, "_assert_stopped"), \
             patch.object(profiles, "_assert_gateway_idle"), \
             patch.object(profiles, "_ensure_private_root"), \
             patch.object(profiles, "_gateway_start"), \
             patch.object(profiles, "_container_up", side_effect=profiles.ProfileError("partial child start")), \
             patch.object(profiles, "_container_down") as down, \
             patch.object(profiles, "_gateway_down") as gateway_down:
            with self.assertRaisesRegex(profiles.ProfileError, "partial child start"):
                profiles._start_services(identity, repo, {}, "hybrid")
        self.assertEqual([call.args[-1] for call in down.call_args_list], ["hybrid_services"])
        gateway_down.assert_called_once_with(identity, repo, {}, Path("/private/gateway"))

    def test_partial_profile_services_are_held(self) -> None:
        status = {"services": [{"name": name, "status": "running"}
                                for name in ("postgres", "dbgate", "mailpit", "silo")]}
        with self.assertRaisesRegex(profiles.ProfileError, "active but incomplete/uncertain services.*silo_client"):
            profiles._assert_profile_services_ready(status, "hybrid_services")
        status["services"].append({"name": "silo_client", "status": "up"})
        profiles._assert_profile_services_ready(status, "hybrid_services")

    def test_partial_managed_listeners_are_held(self) -> None:
        status = {"managed_host_listeners": [{"name": name, "status": "ready"}
                                              for name in ("api", "front")]}
        with self.assertRaisesRegex(profiles.ProfileError, "active but incomplete/uncertain host listeners.*admin"):
            profiles._assert_profile_listeners_ready(status, "hybrid_services")
        status["managed_host_listeners"].append({"name": "admin", "status": "ready"})
        profiles._assert_profile_listeners_ready(status, "hybrid_services")

    def test_profile_start_verifies_detached_up_receipt_against_owned_listener_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
            repo = Path(temporary).resolve() / "main"
            state_root = repo / ".effigy/runtime/host-processes/hybrid_services/effigy"
            state_root.mkdir(parents=True)
            token = "2f4cb9b5af55e39a1def8ae92e19079b"
            scope_response = {
                "schema": "effigy.container.scope.v1",
                "ok": True,
                "checkout": str(repo.resolve()),
                "scope": {"kind": "worktree", "token": token},
            }
            reports = []
            for index, name in enumerate(("api", "front", "admin"), start=1):
                state = {
                    "schema": "effigy.managed.host-listener-state.v1",
                    "owner": f"{token}|hybrid_services|effigy|{name}",
                    "runtime_generation": "runtime-generation",
                    "generation": f"child-generation-{name}",
                    "status": "ready",
                    "address": f"127.0.0.1:{40000 + index}",
                    "internal_url": f"http://127.0.0.1:{40000 + index}",
                    "public_url": f"https://{name}.fixture.test:4443",
                    "route_domain": f"{name}.fixture.test",
                }
                (state_root / f"{name}.listener.json").write_text(json.dumps(state), encoding="utf-8")
                reports.append({
                    "name": name,
                    "status": "ready",
                    **{key: state[key] for key in (
                        "runtime_generation", "generation", "address", "internal_url", "public_url", "route_domain"
                    )},
                    "route_tls": True,
                })
            with patch.object(profiles, "_json_command", return_value=scope_response):
                listeners = profiles._verified_managed_listeners(
                    identity, repo, {}, "hybrid_services", {"managed_host_listeners": reports}
                )
            self.assertEqual([item["name"] for item in listeners], ["api", "front", "admin"])

    def test_profile_start_rejects_changed_listener_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="underlay-profile-admission-") as temporary:
            identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
            repo = Path(temporary).resolve() / "main"
            state_root = repo / ".effigy/runtime/host-processes/hybrid_services/effigy"
            state_root.mkdir(parents=True)
            scope_response = {
                "schema": "effigy.container.scope.v1",
                "ok": True,
                "checkout": str(repo.resolve()),
                "scope": {"kind": "none", "token": None},
            }
            reports = []
            for name in ("api", "front", "admin"):
                state = {
                    "owner": f"main|hybrid_services|effigy|{name}",
                    "runtime_generation": "runtime-generation",
                    "generation": f"child-generation-{name}",
                    "status": "ready",
                    "address": "127.0.0.1:40001",
                    "internal_url": "http://127.0.0.1:40001",
                    "public_url": f"https://{name}.fixture.test:4443",
                    "route_domain": f"{name}.fixture.test",
                }
                (state_root / f"{name}.listener.json").write_text(json.dumps(state), encoding="utf-8")
                reports.append({"name": name, "status": "ready", **state})
            reports[0]["generation"] = "superseded-child-generation"
            with patch.object(profiles, "_json_command", return_value=scope_response):
                with self.assertRaisesRegex(profiles.ProfileError, "startup report and owned listener state disagree: api.generation"):
                    profiles._verified_managed_listeners(
                        identity, repo, {}, "hybrid_services", {"managed_host_listeners": reports}
                    )

    def test_dev_test_accepts_one_selector_and_bounded_timeout(self) -> None:
        self.assertEqual(
            profiles._check_test_task({"UNDERLAY_PROFILE_TEST_TASK": "app-api/test", "UNDERLAY_PROFILE_TEST_TIMEOUT_SECS": "30"}),
            ("app-api/test", 30),
        )
        for selector in ("", "app-api/test --all", "../outside", "qa", "qa:ci:fast", "ci"):
            with self.subTest(selector=selector), self.assertRaises(profiles.ProfileError):
                profiles._check_test_task({"UNDERLAY_PROFILE_TEST_TASK": selector})
        with self.assertRaisesRegex(profiles.ProfileError, "between 1 and 7200"):
            profiles._check_test_task({"UNDERLAY_PROFILE_TEST_TASK": "app-api/test", "UNDERLAY_PROFILE_TEST_TIMEOUT_SECS": "7201"})

    def test_unresolved_test_selector_refuses_before_profile_start(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        env = {"UNDERLAY_PROFILE_TEST_TASK": "app-api/test", "UNDERLAY_PROFILE_TEST_TIMEOUT_SECS": "900"}
        with patch.object(profiles, "_run_process", side_effect=profiles.ProfileError("selector not found")) as plan, \
             patch.object(profiles, "_start_profile") as start:
            with self.assertRaisesRegex(profiles.ProfileError, "selector not found"):
                profiles._test_profile(identity, Path("/fixture"), env, "disposable_test")
        plan.assert_called_once()
        start.assert_not_called()

    def test_dev_test_runs_one_bounded_selector_then_stops_owned_profile(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        repo = Path("/fixture")
        env = {"UNDERLAY_PROFILE_TEST_TASK": "app-api/test", "UNDERLAY_PROFILE_TEST_TIMEOUT_SECS": "30"}
        context = {"routes": {"api": "test.api.fixture.test"}, "https_port": 44321}
        with patch.object(profiles, "_run_process") as invoke, \
             patch.object(profiles, "_start_profile", return_value=context) as start, \
             patch.object(profiles, "_profile_root", return_value=repo / ".effigy/runtime/dev-profiles/test/gateway"), \
             patch.object(profiles, "_profile_env", return_value={"profile": "base"}), \
             patch.object(profiles, "profile_environment", return_value={"profile": "ready"}) as ready_env, \
             patch.object(profiles, "_stop_profile") as stop:
            self.assertEqual(profiles._test_profile(identity, repo, env, "disposable_test"), 0)

        self.assertEqual(invoke.call_count, 2)
        plan_args = invoke.call_args_list[0].args[1]
        action_args = invoke.call_args_list[1].args[1]
        self.assertEqual(plan_args, [identity.binary, "--repo", str(repo), "app-api/test", "--plan"])
        self.assertEqual(invoke.call_args_list[0].kwargs["timeout"], 30)
        self.assertEqual(action_args, [identity.binary, "--repo", str(repo), "app-api/test"])
        self.assertEqual(invoke.call_args_list[1].kwargs["timeout"], 30)
        self.assertIs(invoke.call_args_list[1].kwargs["capture"], False)
        self.assertEqual(invoke.call_args_list[1].kwargs["env"], {"profile": "ready"})
        start.assert_called_once_with(identity, repo, env, "disposable_test")
        ready_env.assert_called_once()
        stop.assert_called_once_with(identity, repo, env, "disposable_test")

    def test_dev_test_stops_owned_profile_after_test_selector_failure(self) -> None:
        identity = profiles.BinaryIdentity("/qualified/source", "/qualified/effigy", "hash", 1, 2, 3, 4)
        repo = Path("/fixture")
        env = {"UNDERLAY_PROFILE_TEST_TASK": "app-api/test", "UNDERLAY_PROFILE_TEST_TIMEOUT_SECS": "30"}
        context = {"routes": {"api": "test.api.fixture.test"}, "https_port": 44321}
        with patch.object(profiles, "_run_process", side_effect=[None, profiles.ProfileError("bounded test failed")]), \
             patch.object(profiles, "_start_profile", return_value=context), \
             patch.object(profiles, "_profile_root", return_value=repo / ".effigy/runtime/dev-profiles/test/gateway"), \
             patch.object(profiles, "_profile_env", return_value={"profile": "base"}), \
             patch.object(profiles, "profile_environment", return_value={"profile": "ready"}), \
             patch.object(profiles, "_stop_profile") as stop:
            with self.assertRaisesRegex(profiles.ProfileError, "bounded test failed"):
                profiles._test_profile(identity, repo, env, "disposable_test")
        stop.assert_called_once_with(identity, repo, env, "disposable_test")


class NestedContextPathTests(unittest.TestCase):
    def test_process_envelope_adapter_and_durable_receipt(self):
        scripts = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(scripts))
        spec = importlib.util.spec_from_file_location("nested_context_qualification", scripts / "qualify-reference-optin.py")
        qualification = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = qualification
        spec.loader.exec_module(qualification)
        seed = "SEEDED_PASSWORD /secret/key?token=SEEDED_TOKEN"
        missing = "container name omitted but `[containers].default` is not defined for implicit targeting"
        def envelope(kind, message):
            return json.dumps({"schema": "effigy.command.v1", "schema_version": 1, "ok": False,
                               "error": {"kind": kind, "message": message, "details": seed}, "result": seed})
        cases = [("negative", 7, envelope("RunnerError", missing), "RunnerError", "default_target_missing", "negative_envelope"),
                 ("negative_zero", 0, envelope("RunnerError", missing), "RunnerError", "default_target_missing", "negative_envelope"),
                 ("malformed", 3, seed, "unknown", "unclassified", "nonjson"),
                 ("unknown", 4, envelope(seed, seed), "unknown", "unclassified", "negative_envelope"),
                 ("unknown_message", 5, envelope("RunnerError", seed), "RunnerError", "unclassified", "negative_envelope"),
                 ("spawn", None, seed, "unknown", "unclassified", "spawn"),
                 ("timeout", -15, seed, "unknown", "unclassified", "timeout")]
        with tempfile.TemporaryDirectory(prefix="underlay-context-path-") as temporary:
            root = Path(temporary).resolve()
            for index, (mode, code, payload, kind, reason, outcome) in enumerate(cases):
                with self.subTest(mode=mode):
                    fixture = root / str(index)
                    fixture.mkdir()
                    (fixture / "effigy.toml").write_text("")
                    adapter = fixture / "adapter"
                    adapter.mkdir()
                    for name in ("managed-vite-listener.mjs", "context-diagnostic.mjs"):
                        shutil.copyfile(scripts / "dev" / name, adapter / name)
                    # Replace only the external process boundary. The real launcher
                    # process/JSON/error code and actual Vite adapter run unchanged.
                    wrapper = f'''import sys, subprocess
from pathlib import Path
sys.path.insert(0, {str(scripts / "dev")!r})
import profile_launcher as p
p._CONTEXT_ACTION = True
p._context_mark("host-inventory", "default.hosts")
p.verify_unchanged = lambda identity: None
class Process:
    pid = 123
    returncode = {code!r}
    calls = 0
    def communicate(self, timeout=None):
        self.calls += 1
        if {mode!r} == "timeout" and self.calls == 1:
            raise subprocess.TimeoutExpired("SEEDED_ARGV", 1)
        return {payload!r}, {seed!r}
def spawn(*args, **kwargs):
    if {mode!r} == "spawn":
        raise OSError({seed!r})
    return Process()
p.subprocess.Popen = spawn
p._stop_owned_process_group = lambda pid: None
try:
    p._json_command(p.BinaryIdentity("source", "/binary", "digest", 1, 2, 3, 4), Path.cwd(), {{}}, "container", "hosts")
except Exception as error:
    p._cli_failure(error)
    sys.exit(1)
raise AssertionError("negative accepted")
'''
                    (adapter / "profile_launcher.py").write_text(wrapper)
                    env = os.environ.copy()
                    env.update({"EFFIGY_MANAGED_HOST_LISTENER_BIND": "127.0.0.1:0",
                                "EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE": str(fixture / "report.json"),
                                "EFFIGY_MANAGED_HOST_LISTENER_GENERATION": "fixture-generation",
                                "EFFIGY_PROFILE_CONTAINER_NAME": "hybrid_services",
                                "EFFIGY_PROFILE_HOST_CONTAINER_NAME": "hybrid_services",
                                "UNDERLAY_PROFILE_REPO": str(fixture), "PYTHONDONTWRITEBYTECODE": "1"})
                    result = subprocess.run(["node", str(adapter / "managed-vite-listener.mjs")], cwd=fixture,
                                            env=env, capture_output=True, text=True, timeout=8)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn("SEEDED", result.stdout + result.stderr)
                    self.assertNotIn("/secret", result.stdout + result.stderr)
                    self.assertFalse((fixture / "report.json").exists())
                    logs = fixture / ".effigy/runtime/host-processes/hybrid_services/effigy"
                    logs.mkdir(parents=True)
                    (logs / "admin.log").write_text(result.stderr)
                    receipts = root / f"receipts-{index}"
                    receipts.mkdir(mode=0o700)
                    journal = qualification.StorageDiagnosticJournal(receipts / "storage-diagnostics.jsonl", fixture)
                    qualification.capture_profile_context_errors([fixture], journal)
                    journal.close()
                    retained = (receipts / "storage-diagnostics.jsonl").read_text()
                    self.assertNotIn("SEEDED", retained)
                    records = [json.loads(line) for line in retained.splitlines()]
                    self.assertEqual(len(records), 1)
                    diagnostic = records[0]["diagnostic"]
                    self.assertEqual(diagnostic["phase"], "host-inventory")
                    self.assertEqual(diagnostic["operation"], "default.hosts")
                    self.assertEqual(diagnostic["exit_status"], 1)
                    self.assertEqual(diagnostic["nested"], {"kind": kind, "reason": reason,
                                                           "outcome": outcome, "exit_status": code})


if __name__ == "__main__":
    unittest.main(verbosity=2)
