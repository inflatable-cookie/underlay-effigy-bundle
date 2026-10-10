"""Hermetic published artifact contract tests; no registry or runtime effects."""
import hashlib
import io
import json
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import silo_fixture as silo


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


if __name__ == "__main__":
    unittest.main()
