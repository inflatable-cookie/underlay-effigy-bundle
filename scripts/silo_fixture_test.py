"""Hermetic published artifact contract tests; no registry or runtime effects."""
import hashlib
import io
import json
import importlib.util
import sys
import stat
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import silo_fixture as silo
from reference_storage_probe import StorageDiagnosticJournal, framing_metadata, sanitize_service_log_line


class RegistryContractTests(unittest.TestCase):
    def fixture(self, *, revision=None, entrypoint=None, subject=None, provenance=True):
        repository = "pgsty/silo"
        pin = dict(silo.PINS[repository])
        objects = {}

        def add(kind, data):
            raw = json.dumps(data).encode()
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            objects[f"/{kind}/{digest}"] = raw
            return digest

        config = add("blobs", {"os": "linux", "architecture": "arm64", "config": {
            "Entrypoint": entrypoint or pin["entrypoint"], "Cmd": ["silo"], "Labels": {
                "org.opencontainers.image.source": f"https://github.com/{repository}",
                "org.opencontainers.image.revision": revision or pin["revision"],
                "org.opencontainers.image.version": silo.RELEASE}}})
        child = add("manifests", {"config": {"digest": config}})
        pin["arm64"] = child
        statement = add("blobs", {"subject": [{"digest": {"sha256": subject or child.split(":")[1]}}],
            "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {
                "externalParameters": {"source": f"https://github.com/{repository}", "revision": pin["revision"]}}}})
        attestation = add("manifests", {"layers": [{"digest": statement}]})
        manifests = [{"digest": child, "platform": {"os": "linux", "architecture": "arm64"}}]
        if provenance:
            manifests.append({"digest": attestation, "annotations": {"vnd.docker.reference.digest": child}})
        pin["digest"] = add("manifests", {"manifests": manifests})

        def open_request(request, timeout):
            url = request if isinstance(request, str) else request.full_url
            if url.startswith("https://auth.docker.io/token?"):
                return io.BytesIO(b'{"token":"test-only"}')
            for suffix, raw in objects.items():
                if url.endswith(suffix):
                    return io.BytesIO(raw)
            raise AssertionError("unexpected registry request")
        return pin, open_request

    def check(self, **kwargs):
        pin, fetch = self.fixture(**kwargs)
        with patch.dict(silo.PINS, {"pgsty/silo": pin}), patch("urllib.request.urlopen", side_effect=fetch):
            return silo.registry_contract("pgsty/silo", "arm64")

    def test_matching_release_is_bounded_and_not_signature_assurance(self):
        result = self.check()
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["sbom_available"])
        self.assertNotIn("environment", result)
        self.assertEqual(result["platform"], "linux/arm64")

    def test_wrong_source_commit_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "revision"):
            self.check(revision="0" * 40)

    def test_wrong_entrypoint_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "entrypoint"):
            self.check(entrypoint=["/unexpected"])

    def test_wrong_attestation_subject_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "subject"):
            self.check(subject="0" * 64)

    def test_missing_provenance_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "provenance"):
            self.check(provenance=False)

    def test_wrong_content_digest_fails_closed(self):
        pin, fetch = self.fixture()
        def corrupt(request, timeout):
            result = fetch(request, timeout)
            if not isinstance(request, str):
                return io.BytesIO(result.read() + b" ")
            return result
        with patch.dict(silo.PINS, {"pgsty/silo": pin}), patch("urllib.request.urlopen", side_effect=corrupt):
            with self.assertRaisesRegex(RuntimeError, "digest verification"):
                silo.registry_contract("pgsty/silo", "arm64")


class ReferenceStoragePatchTests(unittest.TestCase):
    def test_endpoint_patch_is_idempotent_and_explicitly_opt_in(self):
        spec = importlib.util.spec_from_file_location("storage_patch_test_runtime", Path(__file__).with_name("qualify-reference-runtime.py"))
        runtime = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = runtime
        spec.loader.exec_module(runtime)
        with tempfile.TemporaryDirectory(prefix="underlay-silo-patch-test-") as root:
            checkout = Path(root)
            config = checkout / "config/effigy.toml"
            config.parent.mkdir()
            config.write_text('public_host = "api.acme.test"\nurl = "postgres://fixture@localhost/acme"\nallowed_origins = []\ncookie_domain = ".acme.test"\napp_url = "https://admin.acme.test"\nwebauthn_rp_id = "admin.acme.test"\nwebauthn_rp_origin = "https://admin.acme.test"\n')
            source = checkout / "apps/acme-api/crates/api/src/main.rs"
            source.parent.mkdir(parents=True)
            source.write_text('let s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");')
            domains = {"api": "api.acme.test", "front": "acme.test", "admin": "admin.acme.test"}
            runtime.configure_app_urls(checkout, domains, 54321, 54443)
            first = source.read_text()
            runtime.configure_app_urls(checkout, domains, 54321, 54443)
            self.assertEqual(first, source.read_text())
            self.assertIn('EFFIGY_PROFILE_SILO', first)
            self.assertIn('.presign_url_base(public.clone())', first)
            self.assertIn('.public_url_base(format!("{public}/acme-media"))', first)
            self.assertEqual(first.count('https://s3.acme.test'), 1)


class StorageDiagnosticTests(unittest.TestCase):
    def test_journal_is_private_incremental_and_omits_exception_message(self):
        with tempfile.TemporaryDirectory(prefix="underlay-storage-diagnostics-") as root:
            root_path = Path(root)
            fixture = root_path / "fixture"
            diagnostics_dir = root_path / "diagnostics"
            fixture.mkdir(mode=0o700)
            diagnostics_dir.mkdir(mode=0o700)
            path = diagnostics_dir / "storage-diagnostics.jsonl"
            journal = StorageDiagnosticJournal(path, fixture)
            op_id = journal.begin("register", "POST", "/v1/auth/register",
                                  public_name="api.example.test", connect_address="127.0.0.1:44321")
            journal.phase(op_id, "register", "POST", "/v1/auth/register",
                          "response_headers_received", status=201,
                          framing={"content-length": "32"})
            journal.exception(op_id, "register", "POST", "/v1/auth/register",
                              "before_response_body", TimeoutError("presigned-secret-should-not-appear"), status=201)
            journal.close()

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([record["event"] for record in records],
                             ["operation", "operation_phase", "operation_exception"])
            self.assertEqual(records[-1]["exception_type"], "TimeoutError")
            self.assertEqual(records[-1]["status"], 201)
            self.assertNotIn("presigned-secret-should-not-appear", path.read_text())

    def test_auth_trace_patch_artifact_is_private_bounded_and_exact_source_scoped(self):
        with tempfile.TemporaryDirectory(prefix="underlay-storage-diagnostics-") as root:
            root_path = Path(root)
            fixture = root_path / "fixture"
            diagnostics_dir = root_path / "diagnostics"
            fixture.mkdir(mode=0o700)
            diagnostics_dir.mkdir(mode=0o700)
            journal = StorageDiagnosticJournal(diagnostics_dir / "storage-diagnostics.jsonl", fixture)
            payload = b"diff --git a/example b/example\n"
            artifact = Path(journal.write_artifact("reference-auth-diagnostic.patch", payload))
            journal.close()

            self.assertEqual(artifact.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ValueError, "bounded Reference auth fixture patch"):
                journal.write_artifact("unexpected.patch", payload)

    def test_diagnostic_capacity_and_unchanged_snapshot_aggregation(self):
        with tempfile.TemporaryDirectory(prefix='ur.005-journal-controls.') as root:
            root=Path(root).resolve();(root/'fixture').mkdir(mode=0o700);(root/'evidence').mkdir(mode=0o700)
            journal=StorageDiagnosticJournal(root/'evidence/storage-diagnostics.jsonl',root/'fixture')
            for i in range(400):
                journal.append('listener_probe_snapshot',observation_sequence=i,observation_monotonic_ns=i,
                               outcome='before_validation',snapshot={'closed':'same','source_sha256':'a'*64})
            journal.append('listener_probe_snapshot',snapshot={'closed':'changed','source_sha256':'b'*64})
            journal.close()
            rows=[json.loads(line) for line in (root/'evidence/storage-diagnostics.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows),3)
            self.assertEqual(rows[-1]['counts']['listener_probe_snapshot'],399)
            self.assertFalse(rows[-1]['cache_authority'])
            (root/'capacity').mkdir(mode=0o700)
            journal=StorageDiagnosticJournal(root/'capacity/storage-diagnostics.jsonl',root/'fixture')
            with self.assertRaisesRegex(RuntimeError,'diagnostic_capacity_refused'):
                for i in range(100):journal.append('closed_control',count=i,full_source_digest='a'*4096)
            with self.assertRaisesRegex(RuntimeError,'diagnostic_capacity_refused'):journal.assert_admitted()
            journal.close()
            path=root/'capacity/storage-diagnostics.jsonl'
            self.assertLessEqual(path.stat().st_size,128*1024)
            self.assertEqual(json.loads(path.read_text().splitlines()[-1])['event'],'diagnostic_capacity_refused')

    def test_auth_trace_logs_retain_only_allowlisted_phase_fields(self):
        line = ('underlay_profile_auth_diagnostic correlation="fixture-auth-login" '
                'phase="auth_verify_worker" elapsed_ms=8150 outcome="valid"')
        safe = sanitize_service_log_line(line)
        self.assertEqual(
            safe,
            "AUTH_DIAGNOSTIC correlation=fixture-auth-login phase=auth_verify_worker "
            "elapsed_ms=8150 outcome=valid",
        )
        self.assertNotIn("user_id", safe)


class ReferenceAuthTracePatchTests(unittest.TestCase):
    def test_patch_contains_only_the_auth_fixture_files_and_safe_phases(self):
        patch = Path(__file__).with_name("fixtures") / "reference-auth-diagnostic.patch"
        content = patch.read_text(encoding="utf-8")
        self.assertLessEqual(patch.stat().st_size, 24 * 1024)
        targets = {
            line.removeprefix("+++ b/")
            for line in content.splitlines()
            if line.startswith("+++ b/")
        }
        self.assertEqual(targets, {
            "apps/acme-api/crates/api/src/routes/shared/auth/basic.rs",
            "apps/acme-api/crates/auth/src/local/login.rs",
            "apps/acme-api/crates/auth/src/local/mod.rs",
        })
        required_phases = (
            "api_login_handler", "api_login_auth_call", "api_login_role_lookup",
            "api_login_response", "auth_rate_limit", "auth_user_lookup",
            "auth_lockout_check", "auth_credential_lookup", "auth_verify_spawn",
            "auth_verify_worker", "auth_verify_join", "auth_failed_attempt_write",
            "auth_failed_attempt_reset", "auth_credential_last_used",
            "auth_totp_lookup", "auth_session_create",
        )
        additions = "\n".join(
            line[1:] for line in content.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        for phase in required_phases:
            self.assertIn(phase, additions)
        trace_fields = "\n".join(
            line for line in additions.splitlines()
            if any(field in line for field in (
                "tracing::info!", "target:", "correlation =", "phase =",
                "elapsed_ms =", "outcome,",
            ))
        )
        self.assertIn('correlation = "fixture-auth-login"', trace_fields)
        self.assertNotRegex(
            trace_fields,
            r"(?i)email|password|secret|token|authorization|user_id|payload|sql",
        )

    def test_journal_rejects_path_templates_with_queries_and_fixture_local_path(self):
        with tempfile.TemporaryDirectory(prefix="underlay-storage-diagnostics-") as root:
            root_path = Path(root)
            fixture = root_path / "fixture"
            diagnostics_dir = root_path / "diagnostics"
            fixture.mkdir(mode=0o700)
            diagnostics_dir.mkdir(mode=0o700)
            journal = StorageDiagnosticJournal(diagnostics_dir / "storage-diagnostics.jsonl", fixture)
            with self.assertRaisesRegex(ValueError, "redacted path"):
                journal.begin("presigned_put", "PUT", "/bucket/key?signature=value",
                              public_name="s3.example.test", connect_address="127.0.0.1:44321")
            journal.close()
            with self.assertRaisesRegex(RuntimeError, "outside the disposable fixture root"):
                StorageDiagnosticJournal(fixture / "storage-diagnostics.jsonl", fixture)

    def test_framing_and_log_capture_are_allowlisted_and_redacted(self):
        class Response:
            headers = {
                "Content-Length": "17", "Transfer-Encoding": "chunked",
                "Connection": "close", "Content-Type": "application/json",
                "Authorization": "do-not-copy", "Set-Cookie": "do-not-copy",
            }

            def getheader(self, name):
                return next((value for key, value in self.headers.items()
                             if key.lower() == name.lower()), None)

        self.assertEqual(framing_metadata(Response()), {
            "content-length": "17", "transfer-encoding": "chunked",
            "connection": "close", "content-type": "application/json",
        })
        self.assertEqual(
            sanitize_service_log_line("ERROR request GET /acme-media/private-key?X-Amz-Signature=secret timed out"),
            "[sensitive log line omitted]",
        )
        self.assertEqual(
            sanitize_service_log_line('ERROR response={"body":"private payload"}'),
            "[body-bearing log line omitted]",
        )
        self.assertEqual(
            sanitize_service_log_line("WARN config loaded for user=silo-qualification@example.invalid db_configured=true"),
            "WARN config loaded for user=<email> db_configured=true",
        )
        safe = sanitize_service_log_line("WARN request GET https://api.example.test/v1/health status=200")
        self.assertIn("[url omitted]", safe)
        self.assertNotIn("https://", safe)


if __name__ == "__main__":
    unittest.main()
