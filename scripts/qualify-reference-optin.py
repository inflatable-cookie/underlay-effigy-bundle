#!/usr/bin/env python3
"""Exercise the bundle's opt-in selectors in disposable Reference checkouts."""

from __future__ import annotations

import importlib.util
import errno
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from datetime import datetime

from qualification_runtime import require_effigy_binary


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load qualification helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REFERENCE = load_module("reference_profile_helpers", SCRIPTS / "qualify-reference-profiles.py")
RUNTIME = load_module("reference_runtime_helpers", SCRIPTS / "qualify-reference-runtime.py")
from silo_fixture import CLIENT_IMAGE, IMAGE, RELEASE, prepare_published_images  # noqa: E402
from reference_storage_probe import StorageDiagnosticJournal  # noqa: E402
import listener_snapshot  # noqa: E402
import transition_snapshot
import pending_start_identity  # noqa: E402
from listener_snapshot import observed, read_document  # noqa: E402


EFFIGY: str | None = None
RETAINED_LIFECYCLE_RUN = "af3efac4-706f-4cd5-858e-e6d73c61e9fd"
RETAINED_LIFECYCLE_HEAD = "7a31fb0f0c1c93d281f541e2de02ed92e70c86a4"
RETAINED_LIFECYCLE_TASK = "b3ae8bae-190d-42f4-8132-430253bb02fe"


def selector(checkout: Path, name: str, env: dict[str, str], timeout: int = 5400) -> subprocess.CompletedProcess[str]:
    if name == "dev:hybrid:down":
        transition_snapshot.collect_known(checkout, "before_cleanup")
    return RUNTIME.run([EFFIGY, "--repo", str(checkout), name], cwd=checkout,
                        env=env, timeout=timeout, print_output=False)


def effigy_json(checkout: Path, env: dict[str, str], *args: str, timeout: int = 180) -> dict:
    return RUNTIME.effigy_json(EFFIGY, checkout, env, *args, timeout=timeout)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_function_sha256(source: str, function_name: str) -> str:
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == function_name]
    if len(nodes) != 1:
        raise RuntimeError(f"retained input function {function_name} is missing or ambiguous")
    if function_name in ("listener_state", "managed_listener_state"):
        # Normalize only the two audited read/decorator substitutions. Every
        # readiness, ownership, report and route predicate remains in the hash.
        node = nodes[0]
        node.decorator_list = [item for item in node.decorator_list
                               if not (isinstance(item, ast.Name) and item.id == "observed")]
        class DiagnosticRead(ast.NodeTransformer):
            def visit_Call(self, call):
                if (isinstance(call.func, ast.Name) and call.func.id == "read_document"
                        and not call.keywords and len(call.args) == 5
                        and isinstance(call.args[0], ast.Name)
                        and call.args[0].id in ("path", "state_path", "report_path")
                        and isinstance(call.args[1], ast.Name) and call.args[1].id == "checkout"
                        and isinstance(call.args[2], ast.Name) and call.args[2].id == "name"
                        and isinstance(call.args[3], ast.Constant) and call.args[3].value == function_name
                        and isinstance(call.args[4], ast.Constant) and call.args[4].value in ("state", "report")):
                    return ast.parse(f'json.loads({call.args[0].id}.read_text(encoding="utf-8"))').body[0].value
                return self.generic_visit(call)
        node = DiagnosticRead().visit(node)
        return _sha256_bytes(ast.dump(node, include_attributes=False).encode())
    segment = ast.get_source_segment(source, nodes[0])
    if not segment:
        raise RuntimeError(f"retained input function {function_name} has no source segment")
    return _sha256_bytes(segment.encode())


def _source_function_output_prefix_sha256(source: str, function_name: str,
                                          output_name: str) -> str:
    """Hash the function logic through construction of one retained output value."""
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name == function_name]
    if len(nodes) != 1:
        raise RuntimeError(f"retained input function {function_name} is missing or ambiguous")
    function = nodes[0]
    for index, statement in enumerate(function.body):
        if (isinstance(statement, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == output_name
                        for target in statement.targets)):
            prefix = ast.Module(body=function.body[:index + 1], type_ignores=[])
            return _sha256_bytes(ast.dump(prefix, include_attributes=False).encode())
    raise RuntimeError(f"retained input function {function_name} does not construct {output_name}")


def _retained_file_sha256(path: str, reference: str) -> tuple[str, str]:
    current_path = ROOT / path
    current = current_path.read_bytes()
    baseline = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{reference}:{path}"],
        check=True, capture_output=True, timeout=15,
    ).stdout
    current_digest = _sha256_bytes(current)
    baseline_digest = _sha256_bytes(baseline)
    if current_digest != baseline_digest:
        raise RuntimeError(f"retained runtime input changed since accepted head: {path}")
    return current_digest, baseline_digest


def diagnostic_only_recipe_matches(path: str, current: str, baseline: str) -> bool:
    """Compare success recipes after removing only the explicit diagnostic additions."""
    if path.endswith("managed-vite-listener.mjs"):
        current = current.replace('import { decodeContext } from "./context-diagnostic.mjs";\n', '', 1)
        current = current.replace('  const context = decodeContext(contextResult);',
            '  if (contextResult.error || contextResult.status !== 0) {\n'
            '    throw new Error(`qualified profile context lookup failed (status ${contextResult.status ?? "spawn"})`);\n'
            '  }\n  const context = JSON.parse(contextResult.stdout);', 1)
        return current == baseline
    if not path.endswith("profile_launcher.py"):
        return False
    current = re.sub(r"(?m)^([ ]*)# BEGIN nested context diagnostic\n.*?^\1# END nested context diagnostic\n", "", current, flags=re.DOTALL)
    current, count = re.subn(r"# BEGIN context-only diagnostic helpers\n.*?# END context-only diagnostic helpers\n\n\n", "", current, count=1, flags=re.DOTALL)
    if count != 1:
        return False
    current = current.replace('    global _CONTEXT_ACTION\n', '', 1)
    current = current.replace('    _CONTEXT_ACTION = args.action == "context"\n', '', 1)
    current = current.replace('        emit_stderr=not _CONTEXT_ACTION,\n', '')
    diagnostic_tail = ('        _cli_failure(error)\n        raise SystemExit(1)\n'
                       '    except Exception as error:\n        if not _CONTEXT_ACTION:\n            raise\n'
                       '        _cli_failure(error)\n        raise SystemExit(1)')
    if diagnostic_tail not in current:
        return False
    current = current.replace(diagnostic_tail,
        '        print(f"PROFILE REFUSED/FAILED: {error}", file=sys.stderr, flush=True)\n        raise SystemExit(1)', 1)

    class RemovePhaseMarks(ast.NodeTransformer):
        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "_context_mark":
                return None
            return self.generic_visit(node)

        def visit_Subscript(self, node):
            node = self.generic_visit(node)
            if (isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2
                    and isinstance(node.value.elts[0], ast.Call)
                    and isinstance(node.value.elts[0].func, ast.Name)
                    and node.value.elts[0].func.id == "_context_mark"
                    and isinstance(node.slice, ast.Constant) and node.slice.value == 1):
                return node.value.elts[1]
            return node

    normalized = RemovePhaseMarks().visit(ast.parse(current))
    return ast.dump(normalized, include_attributes=False) == ast.dump(ast.parse(baseline), include_attributes=False)


def validate_retained_lifecycle_inputs(prior_diagnostics: Path, source: Path) -> dict:
    """Match accepted auth/storage/assembly inputs without replaying their proofs."""
    prior_diagnostics = prior_diagnostics.resolve(strict=True)
    journal_path = prior_diagnostics / "storage-diagnostics.jsonl"
    cleanup_path = prior_diagnostics / "cleanup-reconciliation.json"
    for path in (journal_path, cleanup_path):
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError(f"retained diagnostic input is not a private regular file: {path.name}")
    rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    events = {row.get("event"): row for row in rows}
    prior = json.loads(cleanup_path.read_text(encoding="utf-8"))
    start = events.get("attempt_started") or {}
    auth_patch = events.get("reference_auth_fixture_patched") or {}
    build = events.get("reference_auth_build_identity") or {}
    storage = events.get("storage_gate_passed") or {}
    images = events.get("pinned_images_prepared") or {}
    if (prior.get("task") != RETAINED_LIFECYCLE_TASK
            or prior.get("worker_run") != RETAINED_LIFECYCLE_RUN
            or prior.get("reference_fixture_root") != start.get("fixture_root")
            or prior.get("runtime", {}).get("signal_sent") is not False
            or prior.get("runtime", {}).get("selector") != "proof:dev-profiles:reference-runtime"):
        raise RuntimeError("retained Queue run or its restart-stop receipt does not match the expected attempt")
    if (start.get("effigy_source") != "8ecd64b37963cd6832a2b6ffa528034c56828504"
            or start.get("effigy_binary_sha256") != "03d10d8e58601896949ff042eb1b179f8cebddcb176d95c48d5573494b4ab324"
            or prior.get("effigy_source") != start.get("effigy_source")
            or prior.get("effigy_binary_sha256") != start.get("effigy_binary_sha256")):
        raise RuntimeError("retained proof used a different Effigy source or private binary")
    if prior.get("bundle_base_head") != "948656bcb02e1fa03bec59eb52aae9c010f43389":
        raise RuntimeError("retained diagnostic packet base does not match the reported runtime attempt")

    reference_source_commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()
    if (reference_source_commit != "fa6a5e89ad83db460a5506b7fa3f915fa767d72a"
            or prior.get("reference_source_commit") != reference_source_commit
            or Path(start.get("reference_source", "")).resolve(strict=True) != source.resolve(strict=True)):
        raise RuntimeError("retained Reference application source identity changed")
    if (storage.get("finalised_state") != "ready" or storage.get("bytes_equal") is not True
            or storage.get("presigned_upload_status") != 200 or storage.get("signed_get_status") != 200
            or storage.get("signed_delete_status") != 204 or prior.get("storage", {}).get("gate") != "passed"):
        raise RuntimeError("retained Reference auth/storage acceptance receipt is incomplete")
    successful_phases = [item for item in prior.get("auth_phase_log", [])
                         if item.get("phase") == "auth_verify_worker" and item.get("outcome") == "valid"]
    if not successful_phases or not prior.get("auth_fixture_patch_sha256"):
        raise RuntimeError("retained login phase receipt is incomplete")

    patch_path = SCRIPTS / "fixtures/reference-auth-diagnostic.patch"
    patch_digest = _sha256_bytes(patch_path.read_bytes())
    if (patch_digest != auth_patch.get("patch_sha256")
            or patch_digest != prior.get("auth_fixture_patch_sha256")
            or _sha256_bytes((prior_diagnostics / "reference-auth-diagnostic.patch").read_bytes()) != patch_digest):
        raise RuntimeError("retained fixture-only auth patch differs from the accepted diagnostic proof")
    fixture_main = Path(prior.get("reference_fixture_root", "")) / "home/reference/main"
    fixture_paths = {
        "main": fixture_main,
        "first": fixture_main.parent / "worktrees/first",
        "second": fixture_main.parent / "worktrees/second",
    }
    fixture_commits = {}
    for name, fixture_path in fixture_paths.items():
        fixture_commits[name] = subprocess.run(
            ["git", "-C", str(fixture_path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if fixture_commits[name] != reference_source_commit:
            raise RuntimeError(f"retained disposable Reference {name} checkout source identity changed")
    fixture_commit = fixture_commits["main"]
    if fixture_commit != reference_source_commit or fixture_commit != build.get("reference_source_commit"):
        raise RuntimeError("retained disposable Reference source checkout identity changed")
    for item in auth_patch.get("files", []):
        file_path = fixture_main / item["path"]
        if _sha256_bytes(file_path.read_bytes()) != item.get("sha256_after"):
            raise RuntimeError(f"retained disposable auth fixture file changed: {item.get('path')}")
    lock_path = fixture_main / "apps/acme-api/Cargo.lock"
    lock_digest = _sha256_bytes(lock_path.read_bytes())
    if (lock_digest != build.get("cargo_lock_sha256")
            or lock_digest != auth_patch.get("cargo_lock_sha256")):
        raise RuntimeError("retained API dependency lock identity changed")
    binary_path = Path(build.get("binary_path", ""))
    if (not binary_path.is_file() or _sha256_bytes(binary_path.read_bytes()) != build.get("binary_sha256")
            or build.get("binary_sha256") != prior.get("reference_api_binary_sha256")):
        raise RuntimeError("retained instrumented Reference API build identity changed")
    if (images.get("silo_image") != IMAGE or images.get("silo_release") != RELEASE
            or images.get("silo_client_image") != CLIENT_IMAGE):
        raise RuntimeError("retained published Silo server/client pin differs from current inputs")

    current_head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", RETAINED_LIFECYCLE_HEAD, current_head],
        check=False, capture_output=True, timeout=15,
    )
    if ancestry.returncode != 0:
        raise RuntimeError("bundle head does not descend from the retained accepted lifecycle attempt")
    effigy_path = Path(EFFIGY).resolve(strict=True)
    effigy_digest = _sha256_bytes(effigy_path.read_bytes())
    if effigy_digest != "5febcae9e40625898beab1f7f5dd93c8fbb67df083b1d16466dabcca89dae8c8":
        raise RuntimeError("retained lifecycle inputs require the reviewed private Effigy binary")
    stable_files = (
        "bundle.toml", "export.toml", "scripts/qualify-reference-runtime.py",
        "scripts/reference_storage_probe.py", "scripts/silo_fixture.py",
        "scripts/qualification_runtime.py", "scripts/dev/managed-rust-listener.py",
        "scripts/dev/sveltekit-public-origin.mjs", "scripts/dev/ui-setup.rhai",
        "scripts/dev/catalog/silo/service.toml", "scripts/dev/catalog/silo/compose.fragment.yml",
        "scripts/dev/catalog/silo-mc/service.toml", "scripts/dev/catalog/silo-mc/compose.fragment.yml",
    )
    file_hashes = {}
    for path in stable_files:
        current_digest, _ = _retained_file_sha256(path, RETAINED_LIFECYCLE_HEAD)
        file_hashes[path] = current_digest
    diagnostic_recipe_hashes = {}
    for path in ("scripts/dev/managed-vite-listener.mjs", "scripts/dev/profile_launcher.py"):
        current = (ROOT / path).read_text(encoding="utf-8")
        baseline = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{RETAINED_LIFECYCLE_HEAD}:{path}"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout
        if not diagnostic_only_recipe_matches(path, current, baseline):
            raise RuntimeError(f"retained production success recipe changed beyond approved diagnostics: {path}")
        diagnostic_recipe_hashes[path] = {"current_sha256": _sha256_bytes(current.encode()),
                                        "accepted_sha256": _sha256_bytes(baseline.encode()),
                                        "success_recipe_matches": True}
    function_inputs = {
        "scripts/qualify-reference-optin.py": (
            "enable_profiles", "install_reference_silo_fixture", "install_reference_auth_trace_fixture",
            "listener_state",
        ),
        "scripts/qualify-reference-profiles.py": (
            "managed_listener_state", "process_ancestry_chain", "install_public_origin_hooks",
            "install_origin_probe",
        ),
        "scripts/qualify-reference-runtime.py": (
            "configure_app_urls", "append_reference_host_processes", "install_public_origin_fixture",
        ),
        "scripts/reference_storage_probe.py": ("prove_reference_upload",),
    }
    function_hashes = {}
    diagnostic_function_sources = {}
    for path, names in function_inputs.items():
        current_text = (ROOT / path).read_text(encoding="utf-8")
        baseline_text = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{RETAINED_LIFECYCLE_HEAD}:{path}"],
            check=True, capture_output=True, text=True, timeout=15,
        ).stdout
        for name in names:
            current_digest = _source_function_sha256(current_text, name)
            baseline_digest = _source_function_sha256(baseline_text, name)
            if current_digest != baseline_digest:
                raise RuntimeError(f"retained profile/storage function changed: {path}:{name}")
            function_hashes[f"{path}:{name}"] = current_digest
            if name in ("listener_state", "managed_listener_state"):
                diagnostic_function_sources[f"{path}:{name}"] = {
                    "source_sha256": _sha256_bytes(current_text.encode()),
                    "retained_validation_ast_sha256": current_digest,
                    "normalization": "observed_decorator_and_exact_read_document_calls_only",
                }

    identity_function = "record_reference_auth_build_identity"
    current_identity_function = (ROOT / "scripts/qualify-reference-optin.py").read_text(encoding="utf-8")
    baseline_identity_function = subprocess.run(
        ["git", "-C", str(ROOT), "show",
         f"{RETAINED_LIFECYCLE_HEAD}:scripts/qualify-reference-optin.py"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout
    identity_logic_match = (
        _source_function_output_prefix_sha256(
            current_identity_function, identity_function, "result")
        == _source_function_output_prefix_sha256(
            baseline_identity_function, identity_function, "result")
    )
    if not identity_logic_match:
        raise RuntimeError("retained API build-identity calculation changed since accepted proof")

    return {
        "schema": "underlay.reference-retained-lifecycle-input-match.v1",
        "prior_queue_result": {
            "task": RETAINED_LIFECYCLE_TASK,
            "run": RETAINED_LIFECYCLE_RUN,
            "head": RETAINED_LIFECYCLE_HEAD,
            "status": "blocked_after_three_instance_and_storage_acceptance",
            "three_instance_acceptance": "accepted callback: production listeners/routes, HTTPS origins, HMR passed",
            "storage_acceptance": "accepted callback and private operation journal matched",
        },
        "retained_fixture_identities": {
            name: {"checkout": str(path.resolve(strict=True)), "reference_source_commit": fixture_commits[name]}
            for name, path in fixture_paths.items()
        },
        "prior_diagnostic_sources": {"journal": str(journal_path), "cleanup": str(cleanup_path)},
        "current_bundle_head": current_head,
        "prior_runtime_attempt_base_head": prior["bundle_base_head"],
        "retained_inputs": {
            "effigy_source": start["effigy_source"],
            "effigy_binary_sha256": start["effigy_binary_sha256"],
            "reference_source_commit": reference_source_commit,
            "reference_auth_patch_sha256": patch_digest,
            "cargo_lock_sha256": lock_digest,
            "reference_api_binary_sha256": build["binary_sha256"],
            "silo_image": IMAGE,
            "silo_client_image": CLIENT_IMAGE,
            "silo_release": RELEASE,
            "stable_bundle_file_hashes": file_hashes,
            "diagnostic_only_recipe_hashes": diagnostic_recipe_hashes,
            "retained_bundle_function_hashes": function_hashes,
            "diagnostic_function_sources": diagnostic_function_sources,
            "build_identity_harness_adjustment": {
                "function": identity_function,
                "calculation_prefix_matches_accepted_head": identity_logic_match,
                "difference": "diagnostic journal is optional for the same returned binary identity",
            },
        },
        "retained_acceptance": {
            "three_instance_routes_https_origins_hmr": "prior Queue result retained; no re-probe",
            "reference_auth_and_signed_storage": "prior sanitized receipt matched; no re-request",
            "storage_gate": "passed",
        },
        "pending_once": [
            "guarded API restart and dependent endpoint handoff",
            "occupied-port partial failure and owner reconciliation",
            "unready-start interruption and exact-scope recovery",
            "foreign-preserving teardown",
            "dev:test bounded execution and cleanup",
        ],
    }


def capture_profile_context_errors(checkouts: list[Path], diagnostics: StorageDiagnosticJournal) -> None:
    launcher = load_module("profile_context_diagnostic_helpers", SCRIPTS / "dev/profile_launcher.py")
    for checkout in checkouts:
        for role in ("front", "admin"):
            path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{role}.log"
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 256 * 1024))
                lines = stream.read(256 * 1024).decode("utf-8", errors="replace").splitlines()
            count = 0
            for line in lines:
                marker = "UNDERLAY_CONTEXT_ERROR "
                offset = line.find(marker)
                if offset < 0 or len(line[offset:]) > 1024:
                    continue
                try:
                    record = launcher.validated_context_record(json.loads(line[offset + len(marker):]))
                except ValueError:
                    continue
                if record is not None:
                    diagnostics.append("profile_context_failed", checkout=str(checkout), role=role, diagnostic=record)
                    count += 1
                    if count >= 24:
                        break


def enable_profiles(checkout: Path, source: Path) -> None:
    manifest_path = checkout / "effigy.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    bundle = REFERENCE.manifest_section(manifest, "bundle")
    if re.search(r"(?m)^profiles\s*=", bundle):
        raise RuntimeError("Reference fixture already has a profile input override")
    base = re.search(r"(?m)^base\s*=\s*\{[^\n]*\}$", bundle)
    if not base:
        raise RuntimeError("Reference fixture has no editable [bundle] declaration")
    profile_input = (
        "profiles = { enabled = true, "
        f"effigy_source = {json.dumps(str(source))}, "
        f"effigy_binary = {json.dumps(str(Path(EFFIGY).resolve()))}, "
        'test_task = "acme-api/test", test_timeout_secs = 900, silo_bucket = "acme-media" }'
    )
    bundle_offset = manifest.index(bundle)
    insert_at = bundle_offset + base.end()
    manifest = manifest[:insert_at] + "\n" + profile_input + manifest[insert_at:]
    manifest_path.write_text(manifest, encoding="utf-8")


def install_reference_silo_fixture(checkout: Path) -> None:
    """Adapt only the disposable Reference API to the profile's Silo env inputs."""
    api_source_path = checkout / "apps/acme-api/crates/api/src/main.rs"
    api_source = api_source_path.read_text(encoding="utf-8")
    old = 'let s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");'
    new = '''let mut s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");
        if std::env::var("EFFIGY_PROFILE_SILO").as_deref() == Ok("true") {
            let endpoint = std::env::var("ACME_S3_ENDPOINT")?;
            let public = std::env::var("ACME_S3_PUBLIC_URL_BASE")?;
            s3_config = s3_config.endpoint_url(endpoint)
                .presign_url_base(public.clone())
                .public_url_base(format!("{public}/acme-media"));
        }'''
    old_count = api_source.count(old)
    new_count = api_source.count(new)
    if old_count == 1 and new_count == 0:
        api_source_path.write_text(api_source.replace(old, new, 1), encoding="utf-8")
    elif old_count == 0 and new_count == 1:
        return
    else:
        raise RuntimeError("Reference Silo fixture adapter source did not match its reviewed exact patch")


REFERENCE_AUTH_TRACE_PATCH = SCRIPTS / "fixtures/reference-auth-diagnostic.patch"
REFERENCE_AUTH_TRACE_FILES = (
    "apps/acme-api/crates/api/src/routes/shared/auth/basic.rs",
    "apps/acme-api/crates/auth/src/local/login.rs",
    "apps/acme-api/crates/auth/src/local/mod.rs",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_retained_restart_inputs(directory: Path) -> dict:
    """Retain completed acceptance, never retired runtime ownership."""
    directory = directory.resolve(strict=True)
    paths = [directory / "result.json", directory / "selector.log",
             directory / "diagnostics/storage-diagnostics.jsonl",
             directory / "diagnostics/interruption-precondition-counterexample.json"]
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024:
            raise RuntimeError("retained restart evidence is not a bounded private regular file")
    result = json.loads(paths[0].read_text())
    counterexample = json.loads(paths[3].read_text())
    head = "f744fed7f810ecdea60ced2de8adff4a48533525"
    if (result.get("head") != head or result.get("exit") != 1
            or counterexample.get("bundle_head") != head
            or result.get("run") != counterexample.get("run")
            or counterexample.get("phase") != "interruption_fixture_preparation_after_owned_down"
            or counterexample.get("journal_sha256") != _sha256_file(paths[2])):
        raise RuntimeError("retained restart evidence does not bind the completed interruption-preparation attempt")
    log = paths[1].read_text()
    for marker in ("PASS owned API child restart, new endpoint report, route replacement, and dependent restarts",
                   "PASS actual Reference API/front/admin listeners and CA-verified private HTTPS routes",
                   "PASS actual Reference front/admin event.url and request.url use configured HTTPS origins",
                   "PASS front/admin Vite HMR WebSockets upgraded with 101 through gateway port"):
        if marker not in log:
            raise RuntimeError("retained restart/origin acceptance marker is missing")
    rows = [json.loads(line) for line in paths[2].read_text().splitlines()]
    events = {row.get("event"): row for row in rows}
    start = events.get("attempt_started") or {}
    if (start.get("effigy_source") != "8ecd64b37963cd6832a2b6ffa528034c56828504"
            or start.get("effigy_binary_sha256") != "03d10d8e58601896949ff042eb1b179f8cebddcb176d95c48d5573494b4ab324"
            or not events.get("retained_acceptance_input_match")
            or not events.get("api_restart_signal_sent")):
        raise RuntimeError("retained restart capability or input receipt is incomplete")
    functions = {}
    for path, names in {
        "scripts/qualify-reference-profiles.py": ("prove_reference_api_restart", "managed_listener_state", "fixture_public_origin_observations"),
        "scripts/qualify-reference-runtime.py": ("observe_routes",),
    }.items():
        current = (ROOT / path).read_text()
        baseline = subprocess.run(["git", "-C", str(ROOT), "show", f"{head}:{path}"],
                                  check=True, capture_output=True, text=True, timeout=15).stdout
        for name in names:
            digest = _source_function_sha256(current, name)
            if digest != _source_function_sha256(baseline, name):
                raise RuntimeError("retained restart validation code changed")
            functions[f"{path}:{name}"] = digest
    build = events.get("reference_auth_build_identity") or {}
    if any(not build.get(key) for key in ("reference_source_commit", "patch_sha256", "cargo_lock_sha256", "compile_selector")):
        raise RuntimeError("retained restart build inputs are incomplete")
    return {"source_head": head, "journal_sha256": _sha256_file(paths[2]),
            "validated_functions": functions,
            "build_inputs": {key: build[key] for key in
                             ("reference_source_commit", "patch_sha256", "cargo_lock_sha256", "compile_selector")},
            "acceptance": "completed API restart/dependent HTTPS/origin/HMR proof retained",
            "ownership": "no retired owner, PID, address or generation transferred"}


def reference_auth_trace_patch_metadata() -> dict:
    patch = REFERENCE_AUTH_TRACE_PATCH.read_bytes()
    if len(patch) > 24 * 1024:
        raise RuntimeError("Reference auth fixture patch exceeded its bounded size")
    lines = patch.decode("utf-8").splitlines()
    targets = {
        line.removeprefix("+++ b/") for line in lines if line.startswith("+++ b/")
    }
    if targets != set(REFERENCE_AUTH_TRACE_FILES):
        raise RuntimeError("Reference auth fixture patch changed files outside its reviewed scope")
    return {
        "path": str(REFERENCE_AUTH_TRACE_PATCH),
        "sha256": hashlib.sha256(patch).hexdigest(),
        "bytes": len(patch),
        "files": list(REFERENCE_AUTH_TRACE_FILES),
        "payload": patch,
    }


def install_reference_auth_trace_fixture(
    checkout: Path, diagnostics: StorageDiagnosticJournal | None = None,
) -> dict:
    """Apply only the bounded login phase trace to this disposable Reference clone."""
    patch = reference_auth_trace_patch_metadata()
    source_commit = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()
    before = {
        relative: _sha256_file(checkout / relative)
        for relative in REFERENCE_AUTH_TRACE_FILES
    }
    checked = subprocess.run(
        ["git", "-C", str(checkout), "apply", "--check", patch["path"]],
        capture_output=True, text=True, timeout=30,
    )
    if checked.returncode != 0:
        raise RuntimeError("Reference auth fixture patch did not match the pinned checkout")
    applied = subprocess.run(
        ["git", "-C", str(checkout), "apply", patch["path"]],
        capture_output=True, text=True, timeout=30,
    )
    if applied.returncode != 0:
        raise RuntimeError("Reference auth fixture patch failed after its exact check")
    after = {
        relative: _sha256_file(checkout / relative)
        for relative in REFERENCE_AUTH_TRACE_FILES
    }
    if any(before[path] == after[path] for path in REFERENCE_AUTH_TRACE_FILES):
        raise RuntimeError("Reference auth fixture patch did not change every expected file")
    lockfile = checkout / "apps/acme-api/Cargo.lock"
    if not lockfile.is_file():
        raise RuntimeError("Reference auth fixture could not retain the API Cargo.lock identity")
    receipt = {
        "reference_source_commit": source_commit,
        "patch_sha256": patch["sha256"],
        "patch_bytes": patch["bytes"],
        "cargo_lock_sha256": _sha256_file(lockfile),
        "files": [
            {"path": relative, "sha256_before": before[relative], "sha256_after": after[relative]}
            for relative in REFERENCE_AUTH_TRACE_FILES
        ],
    }
    if diagnostics is not None:
        receipt["patch_artifact"] = diagnostics.write_artifact(
            "reference-auth-diagnostic.patch", patch["payload"],
        )
        diagnostics.append("reference_auth_fixture_patched", **receipt)
    return receipt


def record_reference_auth_build_identity(
    checkout: Path, env: dict[str, str], diagnostics: StorageDiagnosticJournal | None,
    auth_patch_receipt: dict,
) -> dict:
    target = Path(env["CARGO_TARGET_DIR"]).resolve(strict=True)
    fixture_root = Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]).resolve(strict=True)
    if not target.is_relative_to(fixture_root):
        raise RuntimeError("Reference auth build target escaped the disposable fixture root")
    candidates = (
        target / "debug/acme-api",
        checkout / "apps/acme-api/target/debug/acme-api",
        checkout / "target/debug/acme-api",
    )
    binary = next((candidate for candidate in candidates if candidate.is_file()), None)
    if binary is None:
        raise RuntimeError("instrumented Reference API build artifact was not retained in the private fixture")
    metadata = binary.lstat()
    if not binary.is_file() or binary.is_symlink():
        raise RuntimeError("instrumented Reference API binary is not a regular private build artifact")
    binary = binary.resolve(strict=True)
    result = {
        "reference_source_commit": auth_patch_receipt["reference_source_commit"],
        "patch_sha256": auth_patch_receipt["patch_sha256"],
        "cargo_lock_sha256": auth_patch_receipt["cargo_lock_sha256"],
        "binary_path": str(binary),
        "binary_bytes": metadata.st_size,
        "binary_sha256": _sha256_file(binary),
        "cargo_target_dir": str(target),
        "compile_selector": "acme-api/check",
    }
    if diagnostics is not None:
        diagnostics.append("reference_auth_build_identity", **result)
    return result


def profile_root(checkout: Path, profile: str = "hybrid") -> Path:
    key = "hybrid" if profile == "hybrid" else "test"
    return checkout / ".effigy" / "runtime" / "dev-profiles" / key / "gateway"


def route_domains(checkout: Path, env: dict[str, str]) -> dict[str, str]:
    declarations = {
        "front": "acme.test",
        "admin": "admin.acme.test",
        "api": "api.acme.test",
        "s3": "s3.acme.test",
        "silo": "silo.acme.test",
        "dbgate": "dbgate.acme.test",
        "mailpit": "mailpit.acme.test",
    }
    result: dict[str, str] = {}
    for container in ("hybrid_services",):
        hosts = effigy_json(checkout, env, "container", container, "hosts", "--json")
        for route in hosts.get("routes", []):
            declared, effective = route.get("declared"), route.get("effective")
            if not isinstance(declared, str) or not isinstance(effective, str) or not effective:
                continue
            for role, expected in declarations.items():
                if declared == expected:
                    previous = result.get(role)
                    if previous is not None and previous != effective:
                        raise RuntimeError(f"profile route {role} has conflicting effective names")
                    result[role] = effective
    # The host inventory pairs declared and effective names. Runtime listener
    # state already stores the effective route, so validate it without rewriting
    # the name through this map a second time.
    checkout_hosts = effigy_json(checkout, env, "container", "hosts", "--json")
    checkout_routes = _effective_checkout_routes(checkout_hosts)
    for role in ("front", "admin", "api"):
        _, state = listener_state(checkout, role, env, checkout_routes)
        declared = state.get("declared_route_domain")
        expected_declared = declarations[role]
        if declared != expected_declared:
            raise RuntimeError(f"production profile listener {role} changed its declared route: {declared}")
        effective = checkout_routes.get(expected_declared)
        if not isinstance(effective, str) or not effective:
            raise RuntimeError(f"Effigy checkout host map omitted the effective route for {role}")
        if state.get("route_domain") != effective:
            raise RuntimeError(f"production profile listener {role} did not retain its current effective route")
        result[role] = effective
    missing = set(declarations) - set(result)
    if missing:
        raise RuntimeError(f"production profile selectors omitted declared routes: {sorted(missing)}")
    return result


def service_loopback_port(compose: str, service: str, target: int) -> int:
    """Read the generated loopback binding and require one exact target port."""
    block = re.search(
        rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|^volumes:\n|\Z)",
        compose,
    )
    if block is None:
        raise RuntimeError(f"generated hybrid Compose file omitted service {service}")
    mapping = re.compile(
        rf"(?m)^\s*-\s*[\"']?127\.0\.0\.1:(\d+):{target}(?:/(?:tcp|udp))?[\"']?\s*$"
    )
    ports = [int(match.group(1)) for match in mapping.finditer(block.group(1))]
    if len(ports) != 1 or ports[0] <= 0:
        raise RuntimeError(
            f"generated hybrid Compose service {service} must publish container port {target} "
            f"once on a loopback host port; found {ports}"
        )
    return ports[0]


def gateway_context(checkout: Path, env: dict[str, str], profile: str = "hybrid") -> tuple[Path, int, dict]:
    root = profile_root(checkout, profile)
    gateway = RUNTIME.gateway_json(EFFIGY, env, root, "status")
    if gateway.get("private") is not True or gateway.get("running") is not True:
        raise RuntimeError(f"{profile} profile gateway is not running as a private instance")
    if gateway.get("tls", {}).get("ca_installed") is not False:
        raise RuntimeError("profile gateway reports system trust installation")
    address = gateway.get("https_addr")
    if not isinstance(address, str) or ":" not in address:
        raise RuntimeError("profile gateway has no discovered HTTPS address")
    return root, int(address.rsplit(":", 1)[1]), gateway


def _effective_checkout_routes(host_map: dict) -> dict[str, str]:
    routes: dict[str, str] = {}
    for item in host_map.get("routes", []):
        declared, effective = item.get("declared"), item.get("effective")
        if not isinstance(declared, str) or not isinstance(effective, str) or not effective:
            continue
        previous = routes.get(declared)
        if previous is not None and previous != effective:
            raise RuntimeError(f"Effigy checkout host map has conflicting effective names for {declared}")
        routes[declared] = effective
    return routes


@observed
def listener_state(
    checkout: Path,
    name: str,
    env: dict[str, str],
    effective_routes: dict[str, str] | None = None,
) -> tuple[Path, dict]:
    path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{name}.listener.json"
    state = read_document(path, checkout, name, "listener_state", "state")
    if state.get("status") != "ready" or not state.get("route_owner"):
        raise RuntimeError(f"production profile listener {name} is not owned and ready")
    report_path = path.parent / f"{name}.{state['generation']}.listener-report.json"
    report = read_document(report_path, checkout, name, "listener_state", "report")
    if (report.get("schema") != "effigy.managed.host-listener-report.v1"
            or report.get("generation") != state.get("generation")
            or report.get("address") != state.get("address")
            or state["route_owner"].get("address") != state.get("address")):
        raise RuntimeError(f"profile listener {name} report and owner do not match")
    route_domain = state.get("route_domain")
    public_url = state.get("public_url")
    parsed_public_url = urlsplit(public_url) if isinstance(public_url, str) else None
    if (
        not isinstance(route_domain, str)
        or parsed_public_url is None
        or parsed_public_url.scheme != "https"
        or not parsed_public_url.hostname
        or parsed_public_url.username
        or parsed_public_url.password
        or parsed_public_url.path not in ("", "/")
        or parsed_public_url.query
        or parsed_public_url.fragment
    ):
        raise RuntimeError(f"production profile listener {name} omitted its canonical current HTTPS public URL")
    if parsed_public_url.hostname != route_domain:
        raise RuntimeError(f"production profile listener {name} public URL does not use its effective route")
    routes = effective_routes or _effective_checkout_routes(
        effigy_json(checkout, env, "container", "hosts", "--json")
    )
    declared_domains = [declared for declared, effective in routes.items() if effective == route_domain]
    declared_domain = state.get("declared_route_domain")
    if declared_domain is not None:
        if not isinstance(declared_domain, str) or routes.get(declared_domain) != route_domain:
            raise RuntimeError(f"production profile listener {name} declared/effective route inventory disagrees")
    elif len(declared_domains) == 1:
        declared_domain = declared_domains[0]
    else:
        raise RuntimeError(f"Effigy host inventory did not uniquely identify the declared route for {name}")
    if len(declared_domains) != 1 or declared_domains[0] != declared_domain:
        raise RuntimeError(f"Effigy host inventory has an ambiguous declared route for {name}")
    state["declared_route_domain"] = declared_domain
    return path, state


def prove_owned_bind_exclusion(states: dict[str, dict]) -> list[dict]:
    observations = []
    for name, state in states.items():
        host, port_text = str(state["address"]).rsplit(":", 1)
        contender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            contender.bind((host, int(port_text)))
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise RuntimeError(f"foreign bind probe for owned {name} listener failed unexpectedly: {error}") from error
        else:
            raise RuntimeError(f"a second process could bind the active {name} listener address {state['address']}")
        finally:
            contender.close()
        if not RUNTIME.address_accepts_connection(state["address"]):
            raise RuntimeError(f"owned {name} listener stopped serving after the occupied-bind probe")
        observations.append({"listener": name, "address": state["address"],
                             "foreign_bind_rejected": True, "original_listener_survived": True})
    return observations


def capture_storage_service_logs(checkout: Path, env: dict[str, str],
                                 diagnostics: StorageDiagnosticJournal) -> None:
    api_log = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy/api.log"
    try:
        if api_log.is_file():
            fd = os.open(api_log, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                stream.seek(max(0, os.fstat(stream.fileno()).st_size - 65536))
                tail = stream.read(65536)
            diagnostics.write_log("reference-api.log", tail.decode(
                "utf-8", errors="replace").splitlines())
            diagnostics.append("service_log_source", service="reference-api",
                               source_path=str(api_log), state="captured")
        else:
            diagnostics.append("service_log_source", service="reference-api",
                               source_path=str(api_log), state="missing")
    except BaseException as error:
        diagnostics.append("service_log_capture_failed", service="reference-api",
                           source_path=str(api_log), exception_type=type(error).__name__)

    try:
        result = RUNTIME.run(
            [EFFIGY, "--repo", str(checkout), "container", "hybrid_services", "logs",
             "--service", "silo", "--json"],
            # Pinned CLI logs defaults to follow=false. This is a diagnostic
            # capture budget, independent of all readiness/action deadlines.
            cwd=checkout, env=env, timeout=5, expected=None, print_output=False,
        )
        if result.returncode:
            diagnostics.append("service_log_capture_failed", service="silo", exit=result.returncode,
                               exception_type="EffigyLogsCommandFailed")
            return
        envelope = json.loads(result.stdout)
        logs = (envelope.get("result") or {}).get("logs") if envelope.get("ok") is True else None
        if not isinstance(logs, str):
            diagnostics.append("service_log_capture_failed", service="silo",
                               exception_type="EffigyLogsPayloadMissing")
            return
        diagnostics.write_log("silo-service.log", logs.splitlines())
    except BaseException as error:
        diagnostics.append("service_log_capture_failed", service="silo",
                           exception_type=type(error).__name__)


def append_diagnostic_best_effort(diagnostics: StorageDiagnosticJournal | None,
                                  event: str, **fields) -> None:
    if diagnostics is None:
        return
    try:
        diagnostics.append(event, **fields)
    except BaseException:
        # Diagnostics must not prevent the runner from retiring its owned resources.
        pass


def _profile_probe_state_path(checkout: Path, name: str) -> Path:
    return (checkout / ".effigy/runtime/host-processes/hybrid_services/effigy"
            / f"{name}.listener.json")


def _profile_manifest_hosts(checkout: Path, env: dict[str, str]) -> list[dict]:
    config = RUNTIME.run([EFFIGY, "--repo", str(checkout), "config", "--inspect"],
                         cwd=checkout, env=env, timeout=120, print_output=False).stdout
    marker = "Effective Manifest\n------------------\n"
    if marker not in config:
        raise RuntimeError("Effigy config inspection omitted the effective Reference manifest")
    effective = config.split(marker, 1)[1]
    processes = []
    for section in re.finditer(
        r"(?ms)^\[\[containers\.hybrid_services\.host_processes\]\]\s*(.*?)(?=^\[|\Z)",
        effective,
    ):
        name = re.search(r'(?m)^name\s*=\s*("(?:[^"\\]|\\.)*")\s*$', section.group(1))
        if name is None:
            raise RuntimeError("effective hybrid profile host-process declaration omitted its name")
        try:
            value = json.loads(name.group(1))
        except json.JSONDecodeError as error:
            raise RuntimeError("effective hybrid profile host-process name was malformed") from error
        if not isinstance(value, str):
            raise RuntimeError("effective hybrid profile host-process name was not a string")
        processes.append({"name": value})
    return processes


PROFILE_HOST_PATH = "containers.hybrid_services.host_processes"


def _profile_semantic_hosts(checkout: Path, env: dict[str, str]) -> list[dict]:
    """Inspect the supported typed value in memory; never expose its secret fields."""
    try:
        result = effigy_json(checkout, env, "config", "--inspect", "--path", PROFILE_HOST_PATH,
                             "--json", timeout=120)
    except Exception:
        raise RuntimeError("fixture typed configuration inspection failed") from None
    selected = result.get("selected_value")
    if (result.get("schema") != "effigy.config.v1" or result.get("ok") is not True
            or result.get("selected_path") != PROFILE_HOST_PATH
            or not isinstance(selected, dict) or selected.get("path") != PROFILE_HOST_PATH
            or not isinstance(selected.get("value"), list)):
        raise RuntimeError("fixture host-process inspection has an invalid typed contract")
    hosts = selected["value"]
    if any(not isinstance(host, dict) or not isinstance(host.get("name"), str) for host in hosts):
        raise RuntimeError("fixture host-process inspection has an invalid entry type")
    return hosts


def _fixture_array_extension(original: str) -> str:
    """Edit only the owned incoming layer's bounded path-list declaration."""
    headers = list(re.finditer(r"(?m)^\[manifest\][ \t\r]*(?:#.*)?$", original))
    if len(headers) != 1:
        raise RuntimeError("fixture requires exactly one manifest section")
    start = headers[0].end()
    following = re.search(r"(?m)^\[", original[start:])
    end = start + following.start() if following else len(original)
    section = original[start:end]
    entries = list(re.finditer(r"(?m)^\s*extend\s*=", section))
    if len(entries) > 1 or re.search(r"(?m)^\s*override\s*=", section):
        raise RuntimeError("fixture extension settings are duplicated or conflicting")
    if not entries:
        return original[:start] + "\nextend = " + json.dumps([PROFILE_HOST_PATH]) + original[start:]
    entry = entries[0]
    array = re.match(r"\s*\[([^\]]*)\]", section[entry.end():], re.DOTALL)
    if array is None:
        raise RuntimeError("fixture extend must be a literal path array")
    # Paths use plain quoted identifiers; unsupported expressions fail closed.
    content = re.sub(r"#[^\n]*", "", array.group(1))
    tokens = [token.strip() for token in content.split(",")]
    if tokens and not tokens[-1]:
        tokens.pop()
    paths = []
    for token in tokens:
        match = re.fullmatch(r"(['\"])([A-Za-z0-9_.:-]+)\1", token)
        if match is None:
            raise RuntimeError("fixture extend contains an unsupported path literal")
        paths.append(match.group(2))
    if len(paths) != len(set(paths)):
        raise RuntimeError("fixture extend contains duplicate paths")
    if PROFILE_HOST_PATH not in paths:
        paths.append(PROFILE_HOST_PATH)
    a = start + entry.end()
    b = a + array.end()
    return original[:a] + " " + json.dumps(paths) + original[b:]


def _append_profile_lifecycle_probe(checkout: Path, name: str, route: str, bind: str,
                                    http_status: int, env: dict[str, str]) -> bytes:
    fixture_root = Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]).resolve(strict=True)
    root = checkout.resolve(strict=True)
    if fixture_root not in root.parents:
        raise RuntimeError("lifecycle probe manifest edits are restricted to a disposable Reference checkout")
    if name not in ("interrupted_probe", "collision_probe"):
        raise RuntimeError("lifecycle probe name is invalid")
    host, separator, port = bind.rpartition(":")
    if not separator or host != "127.0.0.1" or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise RuntimeError("lifecycle probe requires an exact IPv4 loopback bind")
    manifest_path = checkout / "effigy.toml"
    if manifest_path.is_symlink() or manifest_path.resolve(strict=True).parent != root:
        raise RuntimeError("fixture manifest must be owned without a symlink escape")
    original_bytes = manifest_path.read_bytes()
    original = original_bytes.decode("utf-8")
    before = _profile_semantic_hosts(checkout, env)
    if [host["name"] for host in before] != ["api", "front", "admin"]:
        raise RuntimeError("fixture requires exactly the original production host-process list")
    if f'name = "{name}"' in original:
        raise RuntimeError("disposable Reference manifest already contains this lifecycle probe")
    command = f'python3 {json.dumps(str(SCRIPTS / "qualification/managed-listener-probe.py"))}'
    block = (
        "\n# Disposable lifecycle probe appended to the assembled hybrid profile.\n"
        "[[containers.hybrid_services.host_processes]]\n"
        f'name = {json.dumps(name)}\n'
        f"run = {json.dumps(command)}\n"
        'cwd = "."\nrestart = "never"\n'
        f"env = {{ EFFIGY_PROFILE_PROBE_HTTP_STATUS = {json.dumps(str(http_status))}, "
        'EFFIGY_PROFILE_WAIT_ON_EADDRINUSE = "1"'
        + (', EFFIGY_PROFILE_PENDING_BARRIER = "1"' if name == "interrupted_probe" else '')
        + ' }\n'
        "[containers.hybrid_services.host_processes.listener]\n"
        f"bind = {json.dumps(bind)}\n"
        "[containers.hybrid_services.host_processes.listener.readiness]\n"
        'path = "/"\nstatus = 200\ntimeout_secs = 90\n'
        "[containers.hybrid_services.host_processes.listener.route]\n"
        f"domain = {json.dumps(route)}\ntls = true\n"
    )
    incoming = _fixture_array_extension(original)
    try:
        manifest_path.write_bytes((incoming + block).encode("utf-8"))
        after = _profile_semantic_hosts(checkout, env)
        if ([host["name"] for host in after] != ["api", "front", "admin", name]
                or after[:3] != before):
            raise RuntimeError("fixture probe extension changed the production host-process values")
    except BaseException:
        manifest_path.write_bytes(original_bytes)
        raise
    return original_bytes


def _profile_probe_diagnostic(state_path: Path) -> dict:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    diagnostic = state.get("diagnostic") or {}
    return {
        "schema": state.get("schema"),
        "status": state.get("status"),
        "generation": state.get("generation"),
        "runtime_generation": state.get("runtime_generation"),
        "claimed_address": diagnostic.get("claimed_address"),
        "report": diagnostic.get("report"),
        "ownership": diagnostic.get("ownership"),
        "http_probe": diagnostic.get("http_probe"),
        "http_status": diagnostic.get("http_status"),
        "route": diagnostic.get("route"),
        "route_owner_present": state.get("route_owner") is not None,
    }


class UncertainProfileOwnership(RuntimeError):
    """A disposable managed profile lacked enough exact state for safe teardown."""


def _verify_profile_probe_failure(checkout: Path, name: str, *, bind: str,
                                   expected_status: int) -> dict:
    state_path = _profile_probe_state_path(checkout, name)
    if not state_path.is_file():
        raise RuntimeError(f"{name} failed startup without retaining its managed owner state")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    diagnostic = state.get("diagnostic") or {}
    if state.get("schema") != "effigy.managed.host-listener-state.v1" or state.get("status") != "failed":
        raise RuntimeError(f"{name} did not retain a failed managed-listener generation")
    if state.get("route_owner") is not None or diagnostic.get("route") != "not_reached":
        raise RuntimeError(f"{name} published or retained an unowned route after failed readiness")
    if diagnostic.get("claimed_address") != bind:
        raise RuntimeError(f"{name} failed-listener receipt did not retain the exact configured bind")
    if diagnostic.get("http_status") != expected_status:
        raise RuntimeError(f"{name} readiness receipt observed HTTP {diagnostic.get('http_status')}, not {expected_status}")
    if expected_status == 503 and diagnostic.get("ownership") != "exclusive_owner_observed":
        raise RuntimeError(f"{name} unready HTTP response did not have a proven exclusive socket owner")
    summary = _profile_probe_diagnostic(state_path)
    if RUNTIME.address_accepts_connection(bind):
        raise RuntimeError(f"{name} failed child still accepts connections after its failure state")
    return summary


def _profile_listener_snapshots(checkout: Path, names: tuple[str, ...],
                                env: dict[str, str]) -> dict[str, dict]:
    snapshots = {}
    for name in names:
        path = _profile_probe_state_path(checkout, name)
        if not path.is_file():
            raise UncertainProfileOwnership(f"production profile omitted the {name} listener owner state")
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("schema") != "effigy.managed.host-listener-state.v1":
            raise UncertainProfileOwnership(f"production profile {name} listener state schema is unknown")
        if state.get("status") == "ready":
            try:
                _, state = listener_state(checkout, name, env)
            except BaseException as error:
                raise UncertainProfileOwnership(
                    f"production profile {name} listener state could not be reconciled"
                ) from error
            if not RUNTIME.address_accepts_connection(state.get("address")):
                raise UncertainProfileOwnership(f"production profile {name} ready listener is not accepting connections")
        elif state.get("status") in {"failed", "stopped"}:
            if state.get("route_owner") is not None:
                raise UncertainProfileOwnership(f"terminal production profile {name} still has a route owner")
        else:
            raise UncertainProfileOwnership(
                f"production profile {name} listener owner state is {state.get('status')!r}"
            )
        for role in ("supervisor", "child", "listener"):
            pid = state.get(f"{role}_pid")
            identity = state.get(f"{role}_start_identity")
            if pid is not None and (not isinstance(pid, int) or not isinstance(identity, dict)
                                    or not isinstance(identity.get("start_seconds"), int)):
                raise UncertainProfileOwnership(f"production profile {name} has incomplete {role} identity")
        snapshots[name] = state
    return snapshots


def _assert_profile_processes_absent(snapshots: dict[str, dict]) -> None:
    try:
        for name, state in snapshots.items():
            for role in ("supervisor", "child", "listener"):
                pid = state.get(f"{role}_pid")
                if pid is None:
                    continue
                identity = state.get(f"{role}_start_identity")
                boot = state.get(f"{role}_boot_identity")
                if (type(pid) is not int or not isinstance(identity, dict)
                        or identity.get("platform") != "macos"
                        or type(identity.get("start_seconds")) is not int or identity["start_seconds"] <= 0
                        or type(identity.get("start_microseconds")) is not int
                        or not 0 <= identity["start_microseconds"] < 1_000_000
                        or not isinstance(boot, str) or pending_start_identity.boot_identity() != boot.upper()):
                    raise pending_start_identity.IdentityUnknown("incomplete precise absence identity")
                if pending_start_identity.kernel_identity(pid) is not None:
                    raise pending_start_identity.IdentityUnknown("recorded or reused process remains")
                if role == "child" and pending_start_identity.group_members(pid):
                    raise pending_start_identity.IdentityUnknown("recorded child group remains")
    except pending_start_identity.IdentityUnknown as error:
        raise UncertainProfileOwnership("profile process or group absence is unproven") from error


def _verify_profile_stopped_records(checkout: Path, snapshots: dict[str, dict], env: dict[str, str],
                                    *, extra_routes: tuple[str, ...] = (),
                                    owned_failed_addresses: tuple[str, ...] = ()) -> None:
    current = {}
    for name, before in snapshots.items():
        state_path = _profile_probe_state_path(checkout, name)
        if not state_path.is_file():
            raise UncertainProfileOwnership(f"production profile down removed the {name} owner state")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("status") != "stopped" or state.get("route_owner"):
            raise UncertainProfileOwnership(f"production profile down did not retain a stopped {name} owner state")
        address = before.get("address")
        if isinstance(address, str):
            sockets = RUNTIME.socket_snapshot(address)
            if sockets.get("listening_pids") or RUNTIME.address_accepts_connection(address):
                raise RuntimeError(f"production profile down left {name} listener {address} open")
        current[name] = state
    for address in owned_failed_addresses:
        sockets = RUNTIME.socket_snapshot(address)
        if sockets.get("listening_pids") or RUNTIME.address_accepts_connection(address):
            raise RuntimeError(f"production profile down left failed owned listener {address} open")
    _assert_profile_processes_absent(snapshots)
    status = effigy_json(checkout, env, "container", "hybrid_services", "status", "--json")
    active_services = [item.get("name") for item in status.get("services", [])
                       if str(item.get("status", "")).lower() in
                       {"up", "running", "created", "restarting"}]
    active_listeners = [item.get("name") for item in status.get("managed_host_listeners", [])
                        if item.get("status") == "ready"]
    if active_services or active_listeners:
        raise RuntimeError(f"production profile down left resources active: services={active_services} listeners={active_listeners}")
    gateway = RUNTIME.gateway_json(EFFIGY, env, profile_root(checkout), "status")
    routes = {item.get("domain") for item in gateway.get("routes", [])}
    expected_routes = {state.get("route_domain") for state in snapshots.values() if state.get("route_domain")}
    expected_routes.update(extra_routes)
    if routes & expected_routes:
        raise RuntimeError(f"production profile down left owned routes published: {sorted(routes & expected_routes)}")
    if gateway.get("running") or routes:
        raise RuntimeError("production profile down left its private gateway or routes active")


def _capture_lifecycle_probe_domain(checkout: Path, env: dict[str, str],
                                    before_states: dict[str, dict], prefix: str) -> str:
    """Capture configured effective identity while live, never infer publication after down."""
    root = checkout.resolve(strict=True)
    fixture = Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]).resolve(strict=True)
    if fixture not in root.parents or prefix not in ("interrupted", "collision"):
        raise RuntimeError("lifecycle route capture requires the owned disposable checkout")
    domains = route_domains(root, env)
    # Prove these are this checkout's current owners, not retired/sibling data.
    _verify_live(root, before_states, env)
    if (set(before_states) != {"api", "front", "admin"}
            or any(before_states[role].get("route_domain") != domains[role]
                   for role in ("api", "front", "admin"))):
        raise RuntimeError("lifecycle route capture differs from current checkout identity")
    return prefix + "." + domains["api"]


def _run_interruptible_profile_start(checkout: Path, env: dict[str, str], diagnostics: StorageDiagnosticJournal,
                                     foreign: list[tuple[Path, dict[str, dict]]], gateway_root: Path,
                                     gateway_port: int, before_states: dict[str, dict]) -> dict[str, dict]:
    probe_domain = _capture_lifecycle_probe_domain(checkout, env, before_states, "interrupted")
    selector(checkout, "dev:hybrid:down", env)
    _verify_stopped(checkout, before_states, env)
    for sibling, states in foreign:
        _verify_live(sibling, states, env)
    original_manifest = _append_profile_lifecycle_probe(
        checkout, "interrupted_probe", probe_domain,
        "127.0.0.1:0", 503, env,
    )
    probe_path = _profile_probe_state_path(checkout, "interrupted_probe")
    process = None
    launch_attempted = False
    scope_reconciled = False
    try:
        for sibling, states in foreign:
            _verify_live(sibling, states, env)
        launch_attempted = True
        process = subprocess.Popen(
            [EFFIGY, "--repo", str(checkout), "dev:hybrid"],
            cwd=checkout, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True,
        )
        deadline = time.monotonic() + 180
        observed = None
        while time.monotonic() < deadline and process.poll() is None:
            if probe_path.is_file():
                raw_bytes = probe_path.read_bytes()
                raw_state = json.loads(raw_bytes)
                if raw_state.get("status") in ("failed", "ready", "stopped"):
                    raise UncertainProfileOwnership("probe completed before pending-start interruption")
                if raw_state.get("status") == "starting" and raw_state.get("child_pid"):
                    # Core writes the child identity after spawn. Read it again after
                    # kernel verification to reject a concurrent generation change.
                    receipt = pending_start_identity.capture_starting(
                        raw_state, before_states["api"]["owner"].rsplit("|", 1)[0] + "|interrupted_probe",
                        raw_state["runtime_generation"], probe_domain)
                    marker_path = probe_path.parent / ("interrupted_probe." + raw_state["generation"] + ".barrier.json")
                    if not marker_path.is_file():
                        time.sleep(0.1)
                        continue
                    marker = json.loads(marker_path.read_bytes())
                    if (marker.get("generation") != receipt["generation"]
                            or marker.get("report_file") != str(probe_path.parent / (
                                "interrupted_probe." + receipt["generation"] + ".listener-report.json"))
                            or marker.get("pid") not in pending_start_identity.group_members(receipt["child"]["pgid"])):
                        raise UncertainProfileOwnership("pending barrier generation or group mismatch")
                    if json.loads(probe_path.read_bytes()) != raw_state:
                        raise UncertainProfileOwnership("pending generation changed during capture")
                    observed = receipt
                    diagnostics.append("pending_start_pretermination", checkout=str(checkout),
                                       selector="dev:hybrid", receipt=receipt,
                                       state_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                                       barrier_generation=marker["generation"], signal_sent=False)
                    break
            time.sleep(0.1)
        if observed is None:
            diagnostics.append(
                "interruption_precondition_failed", checkout=str(checkout),
                selector="dev:hybrid", process_exit=process.poll(),
                probe_state=(_profile_probe_diagnostic(probe_path) if probe_path.is_file() else None),
                signal_sent=False,
            )
            raise RuntimeError("production dev:hybrid did not retain the unready managed-child precondition")
        pgid = os.getpgid(process.pid)
        if pgid != process.pid or process.poll() is not None:
            diagnostics.append("interruption_signal_refused", checkout=str(checkout), selector="dev:hybrid",
                               launcher_pid=process.pid, observed_pgid=pgid,
                               signal_sent=False, probe_state=observed)
            raise RuntimeError("production dev:hybrid startup was no longer an owned interruptible process group")
        current_pending = json.loads(probe_path.read_bytes())
        current_receipt = pending_start_identity.capture_starting(
            current_pending, observed["owner"], observed["runtime_generation"], probe_domain)
        if current_receipt != observed:
            raise UncertainProfileOwnership("pending generation changed before launcher cancellation")
        os.killpg(pgid, signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                os.killpg(pgid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                if process.poll() is None:
                    os.killpg(pgid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=10)
        diagnostics.append(
            "interrupted_profile_start", checkout=str(checkout), selector="dev:hybrid",
            launcher_pid=process.pid, owned_process_group=pgid, signal="SIGINT",
            exit=process.returncode,
            stdout_bytes=len(stdout.encode()) if isinstance(stdout, str) else 0,
            stderr_bytes=len(stderr.encode()) if isinstance(stderr, str) else 0,
            output_disposition="discarded to prevent pipe backpressure and retain no process output",
            probe_state=observed,
        )
        if not probe_path.is_file():
            raise UncertainProfileOwnership("pending probe state disappeared")
        # SIGINT only cancels the launcher. The detached child is stopped by
        # the supported scoped down selector, never by signalling its PID here.
        snapshots = _profile_listener_snapshots(checkout, ("api", "front", "admin"), env)
        for sibling, states in foreign:
            _verify_live(sibling, states, env)
        selector(checkout, "dev:hybrid:down", env)
        terminal = json.loads(probe_path.read_bytes())
        pending_start_identity.cleared_terminal(terminal, observed)
        diagnostics.append("interrupted_profile_scope_down", checkout=str(checkout), selector="dev:hybrid:down",
                           probe_state=_profile_probe_diagnostic(probe_path),
                           child_group=observed["child"]["pgid"], independent_group_absent=True,
                           cancellation="launcher_only", detached_child_cleanup="scoped_down")
        _verify_profile_stopped_records(checkout, snapshots, env, extra_routes=(probe_domain,))
        for sibling, states in foreign:
            _verify_live(sibling, states, env)
        scope_reconciled = True
        (checkout / "effigy.toml").write_bytes(original_manifest)
        for sibling, states in foreign:
            _verify_live(sibling, states, env)
        selector(checkout, "dev:hybrid", env, timeout=1800)
        recovered = {name: listener_state(checkout, name, env)[1]
                     for name in ("api", "front", "admin")}
        _verify_live(checkout, recovered, env)
        for sibling, states in foreign:
            _verify_live(sibling, states, env)
        diagnostics.append("interrupted_profile_recovered", checkout=str(checkout), selector="dev:hybrid",
                           listeners={name: {key: value.get(key) for key in
                                             ("generation", "address", "route_domain")}
                                      for name, value in recovered.items()})
        return recovered
    except pending_start_identity.IdentityUnknown as error:
        diagnostics.append("pending_start_identity_refused", checkout=str(checkout),
                           exception_type="IdentityUnknown", reason=str(error),
                           cleanup_authorized=False)
        raise UncertainProfileOwnership("pending child identity or terminal absence is uncertain") from error
    except UncertainProfileOwnership:
        raise
    except BaseException as error:
        if process is not None and process.poll() is None:
            pgid = os.getpgid(process.pid)
            if pgid != process.pid:
                raise UncertainProfileOwnership("interrupted startup launcher lost its owned process group") from error
            os.killpg(pgid, signal.SIGTERM)
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                process.communicate(timeout=10)
        if not launch_attempted:
            scope_reconciled = True
            (checkout / "effigy.toml").write_bytes(original_manifest)
            raise RuntimeError("interrupted production selector was not launched") from error
        if not probe_path.is_file():
            raise UncertainProfileOwnership("interrupted startup lacks a retained managed probe owner record") from error
        try:
            snapshots = _profile_listener_snapshots(
                checkout, ("api", "front", "admin", "interrupted_probe"), env)
            selector(checkout, "dev:hybrid:down", env)
            _verify_profile_stopped_records(checkout, snapshots, env, extra_routes=(probe_domain,))
            scope_reconciled = True
            (checkout / "effigy.toml").write_bytes(original_manifest)
            for sibling, states in foreign:
                _verify_live(sibling, states, env)
        except BaseException as cleanup_error:
            raise UncertainProfileOwnership(
                "interrupted production profile could not be reconciled from its exact owner records"
            ) from cleanup_error
        raise RuntimeError("interrupted production profile did not meet the required startup proof") from error
    finally:
        (checkout / "effigy.toml").write_bytes(original_manifest)
        if process is not None and process.poll() is None:
            # The caller owns this exact session; only this process group is signaled.
            pgid = os.getpgid(process.pid)
            if pgid == process.pid:
                os.killpg(pgid, signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(pgid, signal.SIGKILL)
                    process.wait(timeout=10)
        if scope_reconciled:
            (checkout / "effigy.toml").write_bytes(original_manifest)


def _run_profile_collision(checkout: Path, foreign_checkout: Path, foreign_states: dict[str, dict],
                           env: dict[str, str], diagnostics: StorageDiagnosticJournal,
                           before_states: dict[str, dict]) -> dict[str, dict]:
    foreign_api = foreign_states["api"]
    collision_domain = _capture_lifecycle_probe_domain(checkout, env, before_states, "collision")
    selector(checkout, "dev:hybrid:down", env)
    _verify_stopped(checkout, before_states, env)
    _verify_live(foreign_checkout, foreign_states, env)
    original_manifest = _append_profile_lifecycle_probe(
        checkout, "collision_probe", collision_domain, foreign_api["address"], 200, env,
    )
    collision_path = _profile_probe_state_path(checkout, "collision_probe")
    safe_failure = False
    process = None
    try:
        process = subprocess.Popen([EFFIGY, "--repo", str(checkout), "dev:hybrid"],
                                   cwd=checkout, env=env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        pending = None
        deadline = time.monotonic() + 180
        while process.poll() is None and time.monotonic() < deadline:
            if collision_path.is_file():
                candidate = json.loads(collision_path.read_bytes())
                if candidate.get("status") == "starting" and candidate.get("child_pid"):
                    pending = pending_start_identity.capture_starting(
                        candidate, before_states["api"]["owner"].rsplit("|", 1)[0] + "|collision_probe",
                        candidate["runtime_generation"], collision_domain)
                    if json.loads(collision_path.read_bytes()) != candidate:
                        raise UncertainProfileOwnership("collision pending generation changed during capture")
                    diagnostics.append("collision_pretermination", checkout=str(checkout), receipt=pending)
                    break
                if candidate.get("status") in ("failed", "ready", "stopped"):
                    break
            time.sleep(0.1)
        if pending is None:
            raise UncertainProfileOwnership("collision lacks a precise pretermination child receipt")
        process.wait(timeout=max(1, 1800 - (180 - max(0, deadline - time.monotonic()))))
        result = subprocess.CompletedProcess(process.args, process.returncode, "", "")
        diagnostics.append("occupied_port_profile_start", checkout=str(checkout), selector="dev:hybrid",
                           exit=result.returncode, stdout_bytes=len(result.stdout.encode()),
                           stderr_bytes=len(result.stderr.encode()),
                           stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                           stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest())
        if result.returncode == 0:
            raise RuntimeError("production dev:hybrid accepted a child bound to a foreign occupied API socket")
        if not collision_path.is_file():
            diagnostics.append("occupied_port_owner_uncertain", checkout=str(checkout),
                               collision_listener="collision_probe", collision_owner_state="missing",
                               cleanup_authorized=False)
            raise UncertainProfileOwnership("occupied-port profile failure did not retain the exact managed-child owner record")
        collision_state = json.loads(collision_path.read_text(encoding="utf-8"))
        diagnostic = collision_state.get("diagnostic") or {}
        if not (collision_state.get("schema") == "effigy.managed.host-listener-state.v1"
                and collision_state.get("status") == "failed"
                and collision_state.get("route_owner") is None
                and diagnostic.get("claimed_address") == foreign_api["address"]
                and diagnostic.get("route") == "not_reached"
                and diagnostic.get("report") in {"absent", "not_observed"}
                and diagnostic.get("ownership") == "not_reached"):
            diagnostics.append("occupied_port_owner_uncertain", checkout=str(checkout),
                               collision_state=_profile_probe_diagnostic(collision_path),
                               cleanup_authorized=False)
            raise UncertainProfileOwnership("occupied-port profile failure retained an ambiguous listener owner state")
        spec_path = collision_path.parent / "collision_probe.spec.json"
        collision_spec = json.loads(spec_path.read_text(encoding="utf-8")) if spec_path.is_file() else {}
        if collision_spec.get("listener", {}).get("bind") != foreign_api["address"]:
            raise RuntimeError("collision probe runtime spec did not retain the exact foreign API bind")
        child_log = collision_path.parent / "collision_probe.log"
        safe_errors = RUNTIME.safe_child_error_excerpt(
            child_log.read_text(encoding="utf-8", errors="replace") if child_log.is_file() else "")
        if not any("address already in use" in line.lower()
                   or re.search(r"errno\s*=\s*(48|98|10048)\b", line, re.IGNORECASE)
                   for line in safe_errors):
            raise RuntimeError("strict occupied-port profile child did not retain EADDRINUSE evidence")
        if RUNTIME.address_accepts_connection(foreign_api["address"]) is not True:
            raise RuntimeError("foreign API listener stopped during the occupied-port profile attempt")
        _verify_live(foreign_checkout, foreign_states, env)
        gateway_root = profile_root(checkout)
        routes = {item.get("domain"): item for item in
                  REFERENCE.private_gateway_status(checkout, gateway_root).get("routes", [])}
        if collision_domain in routes:
            raise RuntimeError("failed occupied-port production selector published a collision route")
        snapshots = _profile_listener_snapshots(checkout, ("api", "front", "admin"), env)
        selector(checkout, "dev:hybrid:down", env)
        _verify_profile_stopped_records(checkout, snapshots, env,
                                        extra_routes=(collision_domain,))
        pending_start_identity.cleared_terminal(json.loads(collision_path.read_bytes()), pending)
        if RUNTIME.address_accepts_connection(foreign_api["address"]) is not True:
            raise RuntimeError("exact production profile down stopped the foreign occupied API listener")
        _verify_live(foreign_checkout, foreign_states, env)
        scope_reconciled = True
        safe_failure = True
        diagnostics.append("occupied_port_profile_reconciled", checkout=str(checkout),
                           selector="dev:hybrid:down", foreign_checkout=str(foreign_checkout),
                           foreign_api_address=foreign_api["address"],
                           foreign_api_route=foreign_api["route_domain"],
                           foreign_api_generation=foreign_api["generation"],
                           collision_state=_profile_probe_diagnostic(collision_path),
                           safe_child_errors=safe_errors[:8], collision_route_absent=True)
    except pending_start_identity.IdentityUnknown as error:
        diagnostics.append("collision_identity_refused", checkout=str(checkout),
                           exception_type="IdentityUnknown", reason=str(error), cleanup_authorized=False)
        raise UncertainProfileOwnership("collision generation or absence is uncertain") from error
    except UncertainProfileOwnership:
        raise
    except BaseException as error:
        if not collision_path.is_file():
            raise UncertainProfileOwnership("occupied-port selector failure has no retained probe owner record") from error
        try:
            snapshots = _profile_listener_snapshots(
                checkout, ("api", "front", "admin", "collision_probe"), env)
            selector(checkout, "dev:hybrid:down", env)
            _verify_profile_stopped_records(checkout, snapshots, env, extra_routes=(collision_domain,))
            _verify_live(foreign_checkout, foreign_states, env)
            scope_reconciled = True
        except BaseException as cleanup_error:
            raise UncertainProfileOwnership(
                "occupied-port selector failure could not be reconciled from exact owner state"
            ) from cleanup_error
        raise RuntimeError("occupied-port failure was safely reconciled but did not meet its proof gate") from error
    finally:
        (checkout / "effigy.toml").write_bytes(original_manifest)
        if process is not None and process.poll() is None:
            if os.getpgid(process.pid) != process.pid:
                raise UncertainProfileOwnership("collision launcher group identity changed")
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    if not safe_failure:
        raise RuntimeError("occupied-port profile lifecycle attempt did not reach a safe reconciled failure")
    selector(checkout, "dev:hybrid", env, timeout=1800)
    recovered = {name: listener_state(checkout, name, env)[1]
                 for name in ("api", "front", "admin")}
    _verify_live(checkout, recovered, env)
    _verify_live(foreign_checkout, foreign_states, env)
    diagnostics.append("occupied_port_profile_recovered", checkout=str(checkout), selector="dev:hybrid",
                       listeners={name: {key: value.get(key) for key in
                                         ("generation", "address", "route_domain")}
                                  for name, value in recovered.items()})
    return recovered


def verify_profile_runtime(checkouts: list[Path], env: dict[str, str], *, storage_only: bool,
                            diagnostics: StorageDiagnosticJournal | None = None,
                            auth_patch_receipt: dict | None = None,
                            remaining_lifecycle: bool = False,
                            retained_inputs: dict | None = None) -> dict:
    service_records: dict[Path, dict] = {}
    app_records: dict[Path, dict[str, dict]] = {}
    api_build_identity: dict | None = None
    started: set[Path] = set()
    held_for_uncertain_owner = False
    receipts: dict = {"production_selectors": [], "instances": [], "cleanup": []}
    if remaining_lifecycle:
        if (storage_only or not retained_inputs
                or retained_inputs.get("retained_acceptance", {}).get("storage_gate") != "passed"):
            raise RuntimeError("remaining-lifecycle mode requires the exact retained acceptance input match")
        receipts["retained_acceptance_input_match"] = retained_inputs
    floor_template = '[manifest]\nminimum_effigy_version = "0.14.1"'
    if floor_template not in (ROOT / "export.toml").read_text(encoding="utf-8"):
        raise RuntimeError("profile input must raise the manifest floor only to 0.14.1")
    try:
        if not remaining_lifecycle:
            for checkout in checkouts:
                config = RUNTIME.run([EFFIGY, "--repo", str(checkout), "config", "--inspect"],
                                     cwd=checkout, env=env, timeout=120, print_output=False).stdout
                for block in ("[containers.hybrid_services]", "[[containers.hybrid_services.host_processes]]",
                              "[containers.disposable_test]", '[tasks."dev:hybrid"]', '[tasks."dev:test"]'):
                    if block not in config:
                        raise RuntimeError(f"opt-in assembly omitted production profile declaration {block}")
                if "[bundle.sources]\nsiblings = false" not in config:
                    raise RuntimeError("opt-in Reference assembly did not preserve sources.siblings=false")
                for name in ("dev:hybrid", "dev:hybrid:status", "dev:hybrid:down",
                             "dev:test", "dev:test:status", "dev:test:down"):
                    plan = RUNTIME.run([EFFIGY, "--repo", str(checkout), name, "--plan"],
                                       cwd=checkout, env=env, timeout=120, print_output=False).stdout
                    command = next((line.removeprefix("Command: ") for line in plan.splitlines()
                                    if line.startswith("Command: ")), "")
                    shell_quote = "'\"'\"'"
                    expected_repo = f"--repo {shell_quote}{checkout}{shell_quote}"
                    if (command.count("--repo") != 1 or expected_repo not in command
                            or "{repo}" in command or "--repo \"'" in command):
                        raise RuntimeError(f"{name} did not pass one well-formed disposable repo path to its launcher")
                    receipts["production_selectors"].append(
                        {"checkout": str(checkout), "selector": name, "plan": "resolved"}
                    )

        for checkout in checkouts:
            started.add(checkout)
            selector(checkout, "dev:hybrid", env, timeout=1800)
            if checkout == checkouts[0] and auth_patch_receipt is not None:
                api_build_identity = record_reference_auth_build_identity(
                    checkout, env, diagnostics, auth_patch_receipt)
            receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid", "exit": 0})
            status = effigy_json(checkout, env, "container", "hybrid_services", "status", "--json")
            service_records[checkout] = status
            services = {str(item.get("name")): str(item.get("status")) for item in status.get("services", [])}
            for name in ("postgres", "dbgate", "mailpit", "silo", "silo_client"):
                if services.get(name, "").lower() not in {"up", "running"}:
                    raise RuntimeError(f"{checkout} production hybrid service {name} is not ready: {services.get(name)}")
            compose_path = checkout / status["compose_file"]
            compose = compose_path.read_text(encoding="utf-8")
            silo_fragment = (checkout / "infra/dev/catalog/silo/compose.fragment.yml").read_text(encoding="utf-8")
            client_fragment = (checkout / "infra/dev/catalog/silo-mc/compose.fragment.yml").read_text(encoding="utf-8")
            silo_service = re.search(r"(?ms)^  silo:\n(.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:|\Z)", compose)
            client_service = re.search(r"(?ms)^  silo_client:\n(.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:|\Z)", compose)
            if ("workspace-rust-bun" in compose
                    or silo_service is None or f"image: {IMAGE}" not in silo_service.group(1)
                    or client_service is None or f"image: {CLIENT_IMAGE}" not in client_service.group(1)
                    or "image: {{ image }}" not in silo_fragment
                    or "image: {{ image }}" not in client_fragment):
                raise RuntimeError("production profile is not using the isolated pinned Silo server and client images")
            gateway_root, gateway_port, gateway = gateway_context(checkout, env)
            domains = route_domains(checkout, env)
            postgres_port = service_loopback_port(compose, "postgres", 5432)
            smtp_port = service_loopback_port(compose, "mailpit", 1025)
            silo_port = service_loopback_port(compose, "silo", 9000)
            endpoint_checks = []
            if not remaining_lifecycle:
                endpoint_checks = [
                    RUNTIME.wait_loopback_service(postgres_port, "postgres"),
                    RUNTIME.wait_loopback_service(smtp_port, "mailpit"),
                    RUNTIME.wait_loopback_service(silo_port, "silo"),
                ]
            checkout_routes = _effective_checkout_routes(
                effigy_json(checkout, env, "container", "hosts", "--json")
            )
            states = {
                name: listener_state(checkout, name, env, checkout_routes)[1]
                for name in ("api", "front", "admin")
            }
            app_records[checkout] = states
            record = {"path": str(checkout), "domains": domains, "gateway": gateway,
                      "gateway_root": str(gateway_root), "gateway_port": gateway_port,
                      "services": services, "ports": {"postgres": postgres_port, "smtp": smtp_port, "silo": silo_port},
                      "readiness": endpoint_checks, "service_compose": str(status["compose_file"])}
            receipts["instances"].append(record)
            record["listeners"] = {name: {"address": state["address"], "route": state["route_domain"],
                                           "generation": state["generation"]}
                                   for name, state in states.items()}
            if remaining_lifecycle:
                record["occupied_bind_probes"] = {
                    "status": "retained_prior_receipt",
                    "reprobed": False,
                }
            else:
                record["occupied_bind_probes"] = prove_owned_bind_exclusion(states)
            selector(checkout, "dev:hybrid:status", env)
            receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid:status", "exit": 0})
            if checkout == checkouts[0] and not remaining_lifecycle:
                selector(checkout, "dev:hybrid", env, timeout=900)
                receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid", "exit": 0,
                                                        "idempotent_existing_profile": True})

            gateway_root = Path(record["gateway_root"])
            gateway_port = int(record["gateway_port"])
            if not remaining_lifecycle:
                RUNTIME.observe_routes(checkout, gateway_root, env, states, gateway_port)
                RUNTIME.prove_silo(checkout, env, int(record["ports"]["silo"]),
                                    f"https://{record['domains']['front']}:{gateway_port}",
                                    container="hybrid_services", service="silo", client_service="silo_client",
                                    bucket_name="acme-media", cleanup_bucket=False)
                silo_route = RUNTIME.prove_silo_gateway_route(checkout, gateway_root, record["domains"], gateway_port)
                if silo_route.get("status") != "passed":
                    raise RuntimeError(f"profile Silo HTTPS/SNI route did not pass: {silo_route}")
                record["silo_gateway"] = silo_route
                for role, path in (("silo", "/"), ("dbgate", "/"), ("mailpit", "/")):
                    route = next((item for item in RUNTIME.REFERENCE.private_gateway_status(checkout, gateway_root).get("routes", [])
                                  if item.get("domain") == record["domains"][role]), None)
                    if not route or route.get("tls") is not True or route.get("cert_ready") is not True:
                        raise RuntimeError(f"profile {role} service route is not privately TLS-ready")
                    ca_context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
                    code, _, _ = REFERENCE.gateway_request(record["domains"][role], gateway_port, ca_context, path,
                                                           {"Host": f"{record['domains'][role]}:{gateway_port}"})
                    if code >= 500:
                        raise RuntimeError(f"profile service HTTPS route {role} returned HTTP {code}")
            if checkout == checkouts[0] and not remaining_lifecycle:
                upload_port = int(record["ports"]["silo"])
                diagnostic_context = None
                if diagnostics is not None:
                    reference_commit = subprocess.run(
                        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                        check=True, capture_output=True, text=True, timeout=15,
                    ).stdout.strip()
                    diagnostic_context = {
                        "fixture_root": env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"],
                        "reference_checkout": str(checkout),
                        "reference_commit": reference_commit,
                        "auth_fixture": auth_patch_receipt or {},
                        "effigy_source": "0412cc7b17f4aab3905e6853a08985270d1454d0",
                        "effigy_binary": str(Path(EFFIGY).resolve()),
                        "effigy_binary_sha256": "be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb",
                        "checkout_generation": states["api"].get("runtime_generation"),
                        "listeners": {
                            name: {key: state.get(key) for key in
                                   ("address", "route_domain", "generation", "runtime_generation")}
                            for name, state in states.items()
                        },
                        "public_names": record["domains"],
                        "host_to_service_loopback": {
                            "gateway_connect_address": f"127.0.0.1:{gateway_port}",
                            "api_listener_address": states["api"].get("address"),
                            "silo_service_endpoint": f"http://127.0.0.1:{upload_port}",
                            "silo_service": "hybrid_services/silo",
                            "silo_image": IMAGE,
                            "silo_release": RELEASE,
                            "silo_client_image": CLIENT_IMAGE,
                        },
                    }
                storage_receipt = RUNTIME.prove_reference_upload(
                    RUNTIME, checkout, env, states, gateway_root, gateway_port, upload_port,
                    service_container="hybrid_services", diagnostics=diagnostics,
                    diagnostic_context=diagnostic_context)
                receipts["reference_storage"] = storage_receipt
                if diagnostics is not None:
                    diagnostics.append(
                        "storage_gate_passed",
                        api_operations=storage_receipt["api_operations"],
                        presigned_upload_status=storage_receipt["presigned_upload_status"],
                        finalised_state=storage_receipt["finalised_state"],
                        signed_get_status=storage_receipt["signed_get_status"],
                        signed_delete_status=storage_receipt["signed_delete_status"],
                        bytes_equal=storage_receipt["bytes_equal"],
                    )
        if remaining_lifecycle:
            receipts["retained_acceptance_reuse"] = {
                "storage_auth_and_three_instance_prerequisites": "input match accepted; no requests or route probes repeated",
                "storage_gate": "passed in prior exact-input receipt",
            }

        addresses = [state["address"] for states in app_records.values() for state in states.values()]
        routes = [state["route_domain"] for states in app_records.values() for state in states.values()]
        ports = [record["ports"]["postgres"] for record in receipts["instances"]]
        if len(addresses) != 3 * len(checkouts) or len(set(addresses)) != len(addresses):
            raise RuntimeError("production profile selectors did not allocate distinct actual host listener addresses")
        if len(set(routes)) != len(routes) or len(set(ports)) != len(ports):
            raise RuntimeError("profile routes or service loopback ports collide across Reference checkouts")
        receipts["distinct_profile_addresses"] = addresses
        receipts["distinct_profile_routes"] = routes
        receipts["distinct_postgres_ports"] = ports

        if not storage_only and len(checkouts) == 3:
            main, before = checkouts[0], app_records[checkouts[0]]
            retained_restart = (retained_inputs or {}).get("restart")
            if retained_restart:
                if api_build_identity is None or any(
                        api_build_identity.get(key) != value
                        for key, value in retained_restart["build_inputs"].items()):
                    raise RuntimeError("fresh API build inputs differ from retained restart proof")
                receipts["api_restart"] = {"status": "retained_prior_proof", **retained_restart}
                if diagnostics is not None:
                    diagnostics.append("retained_restart_input_match", result=retained_restart,
                                       fresh_binary_sha256=api_build_identity["binary_sha256"],
                                       fresh_runtime_identity="current ready owners required by lifecycle capture")
            else:
                restart_before = before["api"]
                restarted = REFERENCE.prove_reference_api_restart(
                    main, Path(receipts["instances"][0]["gateway_root"]), before,
                    expected_api_binary=api_build_identity,
                    diagnostic_sink=diagnostics.append if diagnostics is not None else None,
                    require_durable_preflight=diagnostics is not None)
                if not restarted:
                    raise RuntimeError(f"Reference API restart/dependent endpoint handoff was not proven: {REFERENCE.LAST_API_RESTART_DIAGNOSTIC}")
                _, after_api = listener_state(main, "api", env)
                if (after_api["generation"] == restart_before["generation"]
                        or after_api["address"] == restart_before["address"]):
                    raise RuntimeError("API restart did not change its actual listener generation and address")
                after_states = {"api": after_api}
                for dependent in ("front", "admin"):
                    _, after_dependent = listener_state(main, dependent, env)
                    if after_dependent["generation"] == before[dependent]["generation"]:
                        raise RuntimeError(f"{dependent} did not restart after the API endpoint changed")
                    after_states[dependent] = after_dependent
                app_records[main] = after_states
                RUNTIME.observe_routes(main, Path(receipts["instances"][0]["gateway_root"]), env,
                                      after_states, int(receipts["instances"][0]["gateway_port"]))
                receipts["api_restart"] = {"old_generation": restart_before["generation"],
                                           "new_generation": after_api["generation"],
                                           "old_address": restart_before["address"],
                                           "new_address": after_api["address"],
                                           "dependent_generations_changed": {
                                               name: {"old": before[name]["generation"],
                                                      "new": after_states[name]["generation"]}
                                               for name in ("front", "admin")
                                           },
                                           "dependent_front_admin_routes_reverified": True}
            if remaining_lifecycle or diagnostics is not None:
                foreign = [(checkout, app_records[checkout]) for checkout in checkouts[1:]]
                try:
                    recovered_main = _run_interruptible_profile_start(
                        main, env, diagnostics, foreign,
                        Path(receipts["instances"][0]["gateway_root"]),
                        int(receipts["instances"][0]["gateway_port"]), app_records[main],
                    )
                    receipts["interruption_recovery"] = {
                        "status": "passed", "selector": "dev:hybrid",
                        "interrupted_owner": _profile_probe_diagnostic(
                            _profile_probe_state_path(main, "interrupted_probe")),
                        "recovered_listeners": {
                            name: {key: state.get(key) for key in
                                   ("generation", "address", "route_domain")}
                            for name, state in recovered_main.items()
                        },
                        "foreign_survivors": [str(path) for path, _ in foreign],
                    }
                except UncertainProfileOwnership as error:
                    held_for_uncertain_owner = True
                    receipts["owner_uncertainty"] = {
                        "status": "held", "reason": str(error)[:600],
                        "checkout": str(main), "stage": "interruption_recovery",
                        "cleanup_authorized": False,
                    }
                    append_diagnostic_best_effort(
                        diagnostics, "cleanup_held_uncertain_owner", checkout=str(main),
                        stage="interruption_recovery", reason=type(error).__name__,
                        cleanup_authorized=False,
                    )
                    raise
                app_records[main] = recovered_main

                collision_foreign = checkouts[1]
                try:
                    recovered_main = _run_profile_collision(
                        main, collision_foreign, app_records[collision_foreign], env,
                        diagnostics, app_records[main],
                    )
                    receipts["partial_failure"] = {
                        "status": "passed", "selector": "dev:hybrid",
                        "collision_owner": _profile_probe_diagnostic(
                            _profile_probe_state_path(main, "collision_probe")),
                        "foreign_listener_and_route_preserved": True,
                        "recovered_listeners": {
                            name: {key: state.get(key) for key in
                                   ("generation", "address", "route_domain")}
                            for name, state in recovered_main.items()
                        },
                    }
                except UncertainProfileOwnership as error:
                    held_for_uncertain_owner = True
                    receipts["owner_uncertainty"] = {
                        "status": "held", "reason": str(error)[:600],
                        "checkout": str(main), "stage": "partial_failure",
                        "cleanup_authorized": False,
                    }
                    append_diagnostic_best_effort(
                        diagnostics, "cleanup_held_uncertain_owner", checkout=str(main),
                        stage="partial_failure", reason=type(error).__name__,
                        cleanup_authorized=False,
                    )
                    raise
                app_records[main] = recovered_main
                other_foreign = [(checkout, app_records[checkout]) for checkout in checkouts[1:]]
                receipts["foreign_survivors_after_partial_failure"] = RUNTIME.assert_foreign_instances_live(
                    other_foreign, Path(receipts["instances"][0]["gateway_root"]),
                    int(receipts["instances"][0]["gateway_port"]),
                    "remaining lifecycle partial-failure postcondition",
                )

                foreign_before = {checkout: dict(states) for checkout, states in
                                  ((checkout, app_records[checkout]) for checkout in checkouts[1:])}
                selector(main, "dev:hybrid:down", env)
                receipts["production_selectors"].append(
                    {"checkout": str(main), "selector": "dev:hybrid:down", "exit": 0})
                _verify_stopped(main, app_records[main], env)
                started.discard(main)
                for checkout, before_states in foreign_before.items():
                    _verify_live(checkout, before_states, env)
                receipts["isolated_teardown"] = {
                    "status": "passed",
                    "main_scope": str(main),
                    "foreign_survivors": [str(path) for path in foreign_before],
                    "exact_identity_and_https_checks": True,
                }
                for index, checkout in enumerate(checkouts[1:], start=1):
                    before_states = app_records[checkout]
                    selector(checkout, "dev:hybrid:down", env)
                    receipts["production_selectors"].append(
                        {"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
                    _verify_stopped(checkout, before_states, env)
                    started.discard(checkout)
                    for survivor in checkouts[index + 1:]:
                        _verify_live(survivor, app_records[survivor], env)
            else:
                foreign = [(checkout, app_records[checkout]) for checkout in checkouts[1:]]
                foreign_before = {checkout: dict(states) for checkout, states in foreign}
                selector(main, "dev:hybrid:down", env)
                receipts["production_selectors"].append({"checkout": str(main), "selector": "dev:hybrid:down", "exit": 0})
                _verify_stopped(main, app_records[main], env)
                for checkout, before_states in foreign_before.items():
                    _verify_live(checkout, before_states, env)
                receipts["foreign_survivors_after_main_down"] = [str(path) for path in foreign_before]
                for checkout in checkouts[1:]:
                    selector(checkout, "dev:hybrid:down", env)
                    receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
                    _verify_stopped(checkout, app_records[checkout], env)

            for checkout in checkouts:
                if remaining_lifecycle:
                    continue
                selector(checkout, "dev:hybrid:down", env)
                receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
                _verify_stopped(checkout, app_records[checkout], env)

            test_checkout = main
            selector(test_checkout, "dev:test", env, timeout=5400)
            receipts["production_selectors"].append({"checkout": str(test_checkout), "selector": "dev:test", "exit": 0,
                                                      "configured_task": "acme-api/test", "timeout_secs": 900})
            test_status = effigy_json(test_checkout, env, "container", "disposable_test", "status", "--json")
            active = [service.get("name") for service in test_status.get("services", [])
                      if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}]
            test_gateway = RUNTIME.gateway_json(EFFIGY, env, profile_root(test_checkout, "test"), "status")
            if active or test_gateway.get("running") or test_gateway.get("routes"):
                raise RuntimeError(f"dev:test did not clean its disposable profile: services={active} gateway={test_gateway}")
            receipts["dev_test_cleanup"] = {"services_active": active, "gateway_running": False, "routes": []}
            selector(test_checkout, "dev:test:status", env)
            selector(test_checkout, "dev:test:down", env)
            receipts["production_selectors"].extend([
                {"checkout": str(test_checkout), "selector": "dev:test:status", "exit": 0},
                {"checkout": str(test_checkout), "selector": "dev:test:down", "exit": 0},
            ])
            manifest_path = test_checkout / "effigy.toml"
            manifest = manifest_path.read_text(encoding="utf-8")
            profile_pattern = r'(?m)^profiles = \{(?=[^\n]*enabled = true)[^\n]*test_task = "acme-api/test", test_timeout_secs = 900[^\n]*\}$'
            profile_input, count = re.subn(
                profile_pattern,
                lambda match: match.group(0).replace(
                    'test_task = "acme-api/test", test_timeout_secs = 900',
                    'test_task = "qualification:profile-interrupt", test_timeout_secs = 2',
                ),
                manifest,
                count=1,
            )
            if count != 1:
                raise RuntimeError("could not configure the bounded disposable interruption selector")
            profile_input += (
                '\n\n[tasks."qualification:profile-interrupt"]\n'
                'run = "sleep 30"\nrun_in = "host"\n'
            )
            manifest_path.write_text(profile_input, encoding="utf-8")
            interrupted = RUNTIME.run([EFFIGY, "--repo", str(test_checkout), "dev:test"],
                                      cwd=test_checkout, env=env, timeout=5400,
                                      expected=None, print_output=False)
            if interrupted.returncode == 0:
                raise RuntimeError("the bounded disposable interruption selector unexpectedly succeeded")
            interrupted_status = effigy_json(test_checkout, env, "container", "disposable_test", "status", "--json")
            interrupted_active = [service.get("name") for service in interrupted_status.get("services", [])
                                  if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}]
            interrupted_gateway = RUNTIME.gateway_json(EFFIGY, env, profile_root(test_checkout, "test"), "status")
            if interrupted_active or interrupted_gateway.get("running") or interrupted_gateway.get("routes"):
                raise RuntimeError("timed-out dev:test action did not clean its exact disposable profile")
            receipts["bounded_action_interruption"] = {
                "selector": "qualification:profile-interrupt", "timeout_secs": 2,
                "dev_test_exit": interrupted.returncode, "services_active": interrupted_active,
                "gateway_running": False, "routes": [],
            }

        return receipts
    finally:
        if diagnostics is not None:
            try:
                capture_profile_context_errors(checkouts, diagnostics)
                diagnostics.append("service_log_capture_started", checkout=str(checkouts[0]))
                capture_storage_service_logs(checkouts[0], env, diagnostics)
            except BaseException as error:
                append_diagnostic_best_effort(
                    diagnostics, "service_log_capture_failed", service="capture",
                    exception_type=type(error).__name__)
        # Every profile start is recorded before invocation because a failed or
        # interrupted selector may have created owned resources before returning.
        if held_for_uncertain_owner:
            owner_hold = receipts.get("owner_uncertainty") or {}
            append_diagnostic_best_effort(
                diagnostics, "cleanup_held_uncertain_owner",
                checkouts=[str(checkout) for checkout in sorted(started)],
                stage=owner_hold.get("stage"), reason=owner_hold.get("reason"),
                cleanup_authorized=False,
            )
            receipts["cleanup"].append({
                "held": True,
                "reason": owner_hold.get("reason") or "uncertain managed-child ownership",
                "stage": owner_hold.get("stage"),
                "private_profile_and_exact_scopes_preserved": True,
            })
        for checkout in reversed(checkouts):
            if held_for_uncertain_owner:
                continue
            if checkout not in started:
                continue
            try:
                for name, state in app_records.get(checkout, {}).items():
                    transition_snapshot.collect(checkout, name, state.get("owner"), "before_cleanup")
                append_diagnostic_best_effort(
                    diagnostics, "cleanup_started", checkout=str(checkout),
                    selector="dev:hybrid:down")
                selector(checkout, "dev:hybrid:down", env, timeout=900)
                receipts["cleanup"].append({"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
                append_diagnostic_best_effort(
                    diagnostics, "cleanup_completed", checkout=str(checkout),
                    selector="dev:hybrid:down", exit=0)
            except BaseException as error:
                receipts["cleanup"].append({"checkout": str(checkout), "selector": "dev:hybrid:down",
                                            "held": True, "error": str(error)[:600]})
                append_diagnostic_best_effort(
                    diagnostics, "cleanup_failed", checkout=str(checkout),
                    selector="dev:hybrid:down", exception_type=type(error).__name__)
                raise RuntimeError(f"production profile cleanup is held for {checkout}: {error}") from error


def _verify_live(checkout: Path, states: dict[str, dict], env: dict[str, str]) -> None:
    root, port, gateway = gateway_context(checkout, env)
    if not gateway.get("running"):
        raise RuntimeError(f"foreign profile gateway stopped after another checkout down: {checkout}")
    ca = ssl.create_default_context(cafile=str(root / "ca/rootCA.pem"))
    routes = {item.get("domain"): item for item in gateway.get("routes", [])}
    for name, before in states.items():
        _, after = listener_state(checkout, name, env)
        if any(after.get(key) != before.get(key) for key in
               ("owner", "runtime_generation", "generation", "address", "supervisor_pid",
                "supervisor_start_identity", "child_pid", "child_start_identity",
                "listener_pid", "listener_start_identity")):
            transition_snapshot.collect(checkout, name, before.get("owner"), "live_identity_mismatch")
            raise RuntimeError(f"production profile listener {name} changed relative to its strict live baseline")
        route = routes.get(after["route_domain"])
        if not route or route.get("target") != after["address"] or not RUNTIME.address_accepts_connection(after["address"]):
            raise RuntimeError(f"foreign production profile route/listener {name} was affected")
        path = "/v1/health" if name == "api" else "/"
        status, _, _ = REFERENCE.gateway_request(after["route_domain"], port, ca, path,
                                                  {"Host": f"{after['route_domain']}:{port}"})
        if status != 200:
            raise RuntimeError(f"foreign production profile HTTPS route {name} returned {status}")


def _verify_stopped(checkout: Path, states: dict[str, dict], env: dict[str, str]) -> None:
    host_status = effigy_json(checkout, env, "container", "hybrid_services", "status", "--json")
    active = host_status.get("managed_host_listeners", [])
    if any(item.get("status") == "ready" for item in active):
        raise RuntimeError(f"hybrid host listeners remain active after selector down: {checkout}")
    for name, before in states.items():
        state_path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{name}.listener.json"
        after = json.loads(state_path.read_text(encoding="utf-8"))
        if after.get("status") != "stopped" or after.get("route_owner"):
            raise RuntimeError(f"profile listener {name} did not retain a stopped owner record")
        _assert_profile_processes_absent({name: before})
        if RUNTIME.address_accepts_connection(before["address"]):
            raise RuntimeError(f"profile listener socket remains open after selector down: {before['address']}")
    root = profile_root(checkout)
    gateway = RUNTIME.gateway_json(EFFIGY, env, root, "status")
    if gateway.get("running") or gateway.get("routes"):
        raise RuntimeError("hybrid profile down left a private gateway or routes active")


def main() -> int:
    global EFFIGY
    EFFIGY = require_effigy_binary()
    REFERENCE.EFFIGY = EFFIGY
    RUNTIME.EFFIGY = EFFIGY
    RUNTIME.REFERENCE.EFFIGY = EFFIGY
    source = REFERENCE.reference_source()
    storage_only = os.environ.get("UNDERLAY_PROFILE_STORAGE_ONLY") == "1"
    remaining_lifecycle = os.environ.get("UNDERLAY_PROFILE_REMAINING_LIFECYCLE") == "1"
    if storage_only and remaining_lifecycle:
        raise RuntimeError("storage-only and remaining-lifecycle modes are mutually exclusive")
    diagnostic_dir_value = os.environ.get("UNDERLAY_PROFILE_STORAGE_DIAGNOSTICS_DIR")
    prior_diagnostic_dir_value = os.environ.get("UNDERLAY_PROFILE_PRIOR_DIAGNOSTICS_DIR")
    if (storage_only or remaining_lifecycle) and not diagnostic_dir_value:
        raise RuntimeError("instrumented Reference proof requires UNDERLAY_PROFILE_STORAGE_DIAGNOSTICS_DIR")
    if remaining_lifecycle:
        raise RuntimeError("new qualified Effigy source requires fresh source-sensitive runtime acceptance; historical receipts are not new-source proof")
    if remaining_lifecycle and not prior_diagnostic_dir_value:
        raise RuntimeError("remaining-lifecycle proof requires UNDERLAY_PROFILE_PRIOR_DIAGNOSTICS_DIR")
    retained_inputs = (validate_retained_lifecycle_inputs(Path(prior_diagnostic_dir_value), source)
                       if remaining_lifecycle and prior_diagnostic_dir_value else None)
    restart_directory = os.environ.get("UNDERLAY_PROFILE_PRIOR_RESTART_DIR")
    if restart_directory:
        if not remaining_lifecycle or retained_inputs is None:
            raise RuntimeError("restart receipt reuse requires matched remaining-lifecycle inputs")
        retained_inputs["restart"] = validate_retained_restart_inputs(Path(restart_directory))
    diagnostic_dir = Path(diagnostic_dir_value).expanduser().resolve(strict=True) if diagnostic_dir_value else None
    if remaining_lifecycle:
        prior_journal = Path(retained_inputs["prior_diagnostic_sources"]["journal"]).resolve(strict=True)
        if diagnostic_dir == prior_journal.parent:
            raise RuntimeError("new lifecycle diagnostics must use a separate directory; retained receipts are immutable")
        if list(diagnostic_dir.iterdir()):
            raise RuntimeError("new lifecycle diagnostic directory must be empty")
    fixture_root = RUNTIME.mktemp_root()
    print(f"PRIVATE OPT-IN REFERENCE ROOT: {fixture_root}", flush=True)
    diagnostics = (StorageDiagnosticJournal(diagnostic_dir / "storage-diagnostics.jsonl", fixture_root)
                   if diagnostic_dir is not None else None)
    listener_snapshot.configure(diagnostics.append if diagnostics is not None else None)
    transition_snapshot.configure(diagnostics.append if diagnostics is not None else None, fixture_root)
    if diagnostics is not None:
        diagnostics.append("attempt_started", fixture_root=str(fixture_root),
                           reference_source=str(source),
                           effigy_source="0412cc7b17f4aab3905e6853a08985270d1454d0",
                           effigy_binary=str(Path(EFFIGY).resolve()),
                           effigy_binary_sha256="be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb",
                           selector=("proof:dev-profiles:reference-storage" if storage_only
                                     else "proof:dev-profiles:reference-runtime"),
                           continuation=("remaining_lifecycle" if remaining_lifecycle
                                         else "storage_only" if storage_only else "full_runtime"))
        if retained_inputs is not None:
            diagnostics.append("retained_acceptance_input_match", result=retained_inputs)
    private_home = fixture_root / "home"
    private_home.mkdir(mode=0o700)
    colima_home = fixture_root / "colima-home"
    colima_home.mkdir(mode=0o700)
    private_cargo_home = private_home / ".cargo"
    private_cargo_home.mkdir(mode=0o700)
    private_cargo_target = private_home / ".cargo-target"
    private_cargo_target.mkdir(mode=0o700)
    runtime_env = os.environ.copy()
    real_home = runtime_env.get("HOME", str(Path.home()))
    runtime_env.update({
        "HOME": str(private_home),
        "COLIMA_HOME": str(colima_home),
        "EFFIGY_COMPOSE_BACKEND": "colima",
        "UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(fixture_root),
    })
    runtime_env["RUSTUP_HOME"] = runtime_env.get("RUSTUP_HOME") or str(Path(real_home) / ".rustup")
    runtime_env["CARGO_HOME"] = str(private_cargo_home)
    runtime_env["CARGO_TARGET_DIR"] = str(private_cargo_target)
    reference_root = private_home / "reference"
    reference_root.mkdir(mode=0o700)
    checkouts = REFERENCE.make_reference_instances(source, reference_root)
    if storage_only:
        checkouts = checkouts[:1]
    for checkout in checkouts:
        REFERENCE.point_bundle_at_task_branch(checkout)
    auth_patch_receipt = install_reference_auth_trace_fixture(checkouts[0], diagnostics)
    if not remaining_lifecycle:
        REFERENCE.prove_reference_configuration(checkouts)
    for checkout in checkouts:
        enable_profiles(checkout, Path(os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"]).resolve(strict=True))
        bundle = RUNTIME.effigy_json(EFFIGY, checkout, runtime_env, "bundle", "inspect", "--json")
        if bundle.get("inputs", {}).get("profiles", {}).get("enabled") is not True:
            # `bundle inspect` versions differ in output shape; the effective
            # manifest assertion below remains the authoritative assembly check.
            inspected = RUNTIME.run([EFFIGY, "--repo", str(checkout), "config", "--inspect"],
                                    cwd=checkout, env=runtime_env, timeout=120, print_output=False).stdout
            if "containers.hybrid_services.host_processes" not in inspected:
                raise RuntimeError("Reference fixture did not assemble opt-in production profile declarations")
        install_reference_silo_fixture(checkout)
        RUNTIME.install_public_origin_fixture(checkout)
    REFERENCE.initialize_reference_fixture_secrets(checkouts, runtime_env)
    if not remaining_lifecycle:
        REFERENCE.prove_worktree_plans(checkouts, runtime_env)
    for checkout in checkouts:
        prepared = RUNTIME.run([EFFIGY, "--repo", str(checkout), "workspace:js:prepare"],
                               cwd=checkout, env=runtime_env, timeout=900, print_output=False)
        if prepared.returncode:
            raise RuntimeError(f"Reference workspace preparation failed for {checkout}")

    colima_start_attempted = False
    started_colima = False
    safe_to_purge_colima = False
    attempt_succeeded = False
    try:
        if not remaining_lifecycle:
            compile_result = RUNTIME.run(
                [EFFIGY, "--repo", str(checkouts[0] / "apps/acme-api"), "check"],
                cwd=checkouts[0] / "apps/acme-api", env=runtime_env,
                timeout=900, expected=None, print_output=False,
            )
            append_diagnostic_best_effort(
                diagnostics, "reference_auth_fixture_compile",
                selector="acme-api/check", exit=compile_result.returncode,
                reference_source_commit=auth_patch_receipt["reference_source_commit"],
                patch_sha256=auth_patch_receipt["patch_sha256"],
                cargo_lock_sha256=auth_patch_receipt["cargo_lock_sha256"],
            )
            if compile_result.returncode != 0:
                raise RuntimeError("instrumented disposable Reference auth fixture compile failed")
        from formatter_provenance import bind_host, bound_colima, observe
        bind_host(runtime_env)
        for key in ('DOCKER_HOST','DOCKER_CONTEXT','COLIMA_PROFILE'):
            if key in runtime_env:raise RuntimeError('foreign runtime override refused')
        colima_start_attempted = True
        RUNTIME.run([bound_colima(runtime_env), "start", "--profile", "effigy", "--runtime", "containerd",
                     "--cpu", "6", "--memory", "8", "--disk", "64"],
                    env=runtime_env, timeout=1200)
        started_colima = True
        if diagnostics is None:raise RuntimeError('full-profile finite diagnostics required')
        observe(runtime_env,fixture_root,diagnostics)
        import importlib.util as _import_util
        _spec=_import_util.spec_from_file_location('full_image_interfaces',ROOT/'scripts/qualify-storage-correlation.py')
        _image=_import_util.module_from_spec(_spec);_spec.loader.exec_module(_image)
        image_receipt = prepare_published_images(fixture_root,runtime_env,
            client_probe=lambda shape:_image.client_image_provenance(runtime_env,diagnostics,shape))
        _image.image_interfaces(runtime_env,diagnostics,__import__('secrets').token_hex(16))
        if diagnostics is not None:
            diagnostics.append("pinned_images_prepared", silo_image=IMAGE,
                               silo_release=RELEASE, silo_client_image=CLIENT_IMAGE)
        receipts = verify_profile_runtime(checkouts, runtime_env, storage_only=storage_only,
                                          diagnostics=diagnostics,
                                          auth_patch_receipt=auth_patch_receipt,
                                          remaining_lifecycle=remaining_lifecycle,
                                          retained_inputs=retained_inputs)
        # Scoped down/current child-group/socket/route checks are owned by
        # verify_profile_runtime. Never turn those observations into retirement
        # or purge authority; newly created VM/images/volumes remain held.
        receipts["resource_disposition"] = {"vm_images_volumes":"held", "retirement_proven":False}
        for checkout in checkouts:
            for state_name in ("hybrid","test"):
                gateway=RUNTIME.gateway_json(EFFIGY,runtime_env,profile_root(checkout,state_name),"status")
                if gateway.get("running") or gateway.get("routes"):
                    raise RuntimeError("new private gateway remains held after scoped cleanup")
        receipts["effigy_source"] = "0412cc7b17f4aab3905e6853a08985270d1454d0"
        receipts["effigy_binary"] = str(Path(EFFIGY).resolve())
        receipts["effigy_binary_sha256"] = "be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb"
        receipts["silo_images"] = image_receipt
        receipts["reference_source"] = str(source)
        receipt_path = fixture_root / "profile-selector-receipts.json"
        receipt_path.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        attempt_succeeded = True
        print(f"PASS production opt-in Reference profile selectors; receipt: {receipt_path}", flush=True)
        return 0
    except BaseException as error:
        append_diagnostic_best_effort(
            diagnostics, "attempt_failed", phase="production_profile_runtime_or_cleanup",
            exception_type=type(error).__name__)
        raise
    finally:
        if diagnostics is not None:
            try:
                diagnostics.append("attempt_finished", colima_start_attempted=colima_start_attempted,
                                   colima_started=started_colima,
                                   selector_succeeded=attempt_succeeded,
                                   private_profile_purged=safe_to_purge_colima,
                                   disposition=("purged" if safe_to_purge_colima else
                                                "held" if started_colima else "not_started"))
            except BaseException:
                pass
            finally:
                diagnostics.close()
        if colima_start_attempted and not safe_to_purge_colima:
            print("PRIVATE COLIMA PROFILE HELD: VM/images/volumes are retained; scoped cleanup does not authorize retirement",
                  file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"OPT-IN REFERENCE PROFILE PROOF FAILED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
