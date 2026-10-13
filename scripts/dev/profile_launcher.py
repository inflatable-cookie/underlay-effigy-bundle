#!/usr/bin/env python3
"""Gate and run the bundle's opt-in Underlay development profiles."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import secrets
import stat
import subprocess
import sys
import time

# Exported sibling asset; never import qualification scripts into production.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import silo_client


SUPPORTED_SOURCE = "0412cc7b17f4aab3905e6853a08985270d1454d0"
SUPPORTED_BINARY_SHA256 = "be6ef9733e308b1c410c79d0d70bb8ee1f0141f7b4cc67bd6fe67744629d93eb"
SUPPORTED_VERSION = "effigy v0.14.1"
SUPPORTED_SYSTEM = "Darwin"
SUPPORTED_MACHINE = "arm64"
SILO_USER = "minioadmin"
SILO_PASSWORD = "minioadmin"
PROFILE_CONTAINERS = {
    "hybrid": ("hybrid_services", "hybrid_services"),
    "disposable_test": ("disposable_test", "disposable_test"),
}


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class BinaryIdentity:
    source: str
    binary: str
    digest: str
    device: int
    inode: int
    size: int
    mtime_ns: int


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(source: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProfileError(f"cannot verify the qualified Effigy source checkout: {error}") from error
    return result.stdout.strip()


def verify_binary(
    source_value: str | None,
    binary_value: str | None,
    *,
    system: str | None = None,
    machine: str | None = None,
    expected_source: str = SUPPORTED_SOURCE,
    expected_hash: str = SUPPORTED_BINARY_SHA256,
) -> BinaryIdentity:
    system = system or platform.system()
    machine = machine or platform.machine().lower()
    if (system, machine) != (SUPPORTED_SYSTEM, SUPPORTED_MACHINE):
        raise ProfileError(
            "opt-in hybrid/test profiles are qualified only for macOS arm64; "
            f"this host is {system}/{machine}. The container-only profile remains available."
        )
    if not source_value or not binary_value:
        raise ProfileError(
            "set bundle inputs profiles.effigy_source and profiles.effigy_binary "
            "to the clean qualified Effigy source checkout and absolute binary"
        )

    try:
        source = Path(source_value).expanduser().resolve(strict=True)
        binary = Path(binary_value).expanduser().resolve(strict=True)
    except OSError as error:
        raise ProfileError(f"qualified Effigy source or binary path is unavailable: {error}") from error

    if not source.is_dir():
        raise ProfileError("qualified Effigy source path must be a Git checkout directory")
    if _git(source, "rev-parse", "--show-toplevel") != str(source):
        raise ProfileError("qualified Effigy source path must name the checkout root")
    revision = _git(source, "rev-parse", "HEAD")
    if revision != expected_source:
        raise ProfileError(f"Effigy source must be {expected_source}, got {revision}")
    if _git(source, "status", "--porcelain"):
        raise ProfileError("qualified Effigy source checkout has changes; restore it before using this profile")

    try:
        before = binary.stat()
        if not stat.S_ISREG(before.st_mode) or not os.access(binary, os.X_OK):
            raise ProfileError("qualified Effigy binary must be an executable regular file")
        digest = _hash_file(binary)
        version_result = subprocess.run(
            [str(binary), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = version_result.stdout.strip()
        after = binary.stat()
        final_digest = _hash_file(binary)
    except ProfileError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise ProfileError(f"cannot verify or invoke the absolute Effigy binary: {error}") from error

    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or digest != final_digest:
        raise ProfileError("Effigy binary changed while its identity was being validated")
    if version != SUPPORTED_VERSION:
        raise ProfileError(f"Effigy binary must report {SUPPORTED_VERSION!r}, got {version!r}")
    if digest != expected_hash:
        raise ProfileError(
            "Effigy binary SHA-256 is not the qualified macOS arm64 build; "
            f"expected {expected_hash}, got {digest}"
        )
    return BinaryIdentity(
        source=str(source),
        binary=str(binary),
        digest=digest,
        device=after.st_dev,
        inode=after.st_ino,
        size=after.st_size,
        mtime_ns=after.st_mtime_ns,
    )


# BEGIN context-only diagnostic helpers
_CONTEXT_ACTION = False
_CONTEXT_PHASE = "admission"
_CONTEXT_OPERATION = "verify"
CONTEXT_PHASES = {"admission", "configuration", "service-status", "compose-bindings", "host-inventory", "gateway-status", "gateway-port", "route-validation", "service-port"}
CONTEXT_OPERATIONS = {"verify", "private-root", "compose", "default.hosts", "gateway.status", "gateway.https", "routes", "postgres", "smtp", "mailpit_http", "silo", "silo_console", "dbgate", "hybrid_services.status", "disposable_test.status", "hybrid_services.hosts", "disposable_test.hosts"}
CONTEXT_CLASSES = {"ProfileError", "OSError", "FileNotFoundError", "PermissionError", "TimeoutExpired", "JSONDecodeError", "ValueError", "TypeError", "other"}
CONTEXT_MESSAGES = {"operation_failed", "command_timeout", "invalid_json", "source_or_binary_refused", "private_gateway_unavailable", "loopback_binding_unavailable", "binding_conflict", "effective_route_unavailable", "file_unavailable", "permission_denied"}
NESTED_KINDS = {"RunnerError", "unknown"}
NESTED_RESULTS = {"negative_envelope", "nonjson", "invalid_envelope", "nonzero_success", "spawn", "timeout"}
NESTED_REASONS = {"unclassified", "default_target_missing", "container_not_defined", "working_directory_missing", "project_name_conflict"}


def nested_failure(kind: str, reason: str, outcome: str, code: int | None) -> ProfileError:
    error = ProfileError("nested context command refused")
    error.nested = {"kind": kind, "reason": reason, "outcome": outcome, "exit_status": code}
    return error


def context_json_result(result: subprocess.CompletedProcess) -> dict:
    # Source 8ecd64b: cli/output/envelope.rs, cli/entrypoint.rs and
    # crates/effigy-containers/src/policy/{load,project}.rs. No substitutions emitted.
    try:
        envelope = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise nested_failure("unknown", "unclassified", "nonjson", result.returncode) from None
    if (not isinstance(envelope, dict) or envelope.get("schema") != "effigy.command.v1"
            or envelope.get("schema_version") != 1 or type(envelope.get("ok")) is not bool):
        raise nested_failure("unknown", "unclassified", "invalid_envelope", result.returncode)
    if not envelope["ok"]:
        negative = envelope.get("error")
        negative = negative if isinstance(negative, dict) else {}
        kind = negative.get("kind")
        kind = kind if isinstance(kind, str) and kind in NESTED_KINDS else "unknown"
        reason = "unclassified"
        message = negative.get("message")
        if kind == "RunnerError" and isinstance(message, str) and len(message) <= 16384:
            if message == "container name omitted but `[containers].default` is not defined for implicit targeting":
                reason = "default_target_missing"
            elif re.fullmatch(r"container `[^`\n]+` is not defined in `\[containers\]` \(available: [^\n]*\)", message):
                reason = "container_not_defined"
            elif re.fullmatch(r"container `([^`\n]+)` must declare `\[containers\.\1\]\.working_dir` or a repo-root host mount for CWD mapping", message):
                reason = "working_directory_missing"
            elif re.fullmatch(r"containers must resolve to unique `project_name` values when more than one container is declared; duplicate effective project names: [^\n]+", message):
                reason = "project_name_conflict"
        raise nested_failure(kind, reason, "negative_envelope", result.returncode)
    if result.returncode != 0:
        raise nested_failure("unknown", "unclassified", "nonzero_success", result.returncode)
    value = envelope.get("result")
    return value if isinstance(value, dict) else {}


def validated_nested(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    fields = {"kind": NESTED_KINDS, "reason": NESTED_REASONS, "outcome": NESTED_RESULTS}
    if any(not isinstance(value.get(key), str) or value[key] not in allowed for key, allowed in fields.items()):
        return None
    code = value.get("exit_status")
    if code is not None and (type(code) is not int or not -255 <= code <= 255):
        return None
    return {"kind": value["kind"], "reason": value["reason"], "outcome": value["outcome"], "exit_status": code}


def _context_mark(phase: str, operation: str) -> None:
    global _CONTEXT_PHASE, _CONTEXT_OPERATION
    _CONTEXT_PHASE, _CONTEXT_OPERATION = phase, operation


def context_error_record(error: Exception) -> dict:
    error_class = type(error).__name__
    if error_class not in CONTEXT_CLASSES:
        error_class = "other"
    # Only fixed classifications are emitted; exception text stays in memory.
    message = "operation_failed"
    text = str(error)
    if isinstance(error, subprocess.TimeoutExpired) or "exceeded its" in text:
        message = "command_timeout"
    elif isinstance(error, json.JSONDecodeError) or "did not return JSON" in text:
        message = "invalid_json"
    elif isinstance(error, PermissionError):
        message = "permission_denied"
    elif isinstance(error, FileNotFoundError):
        message = "file_unavailable"
    elif _CONTEXT_PHASE == "admission":
        message = "source_or_binary_refused"
    elif "private gateway" in text:
        message = "private_gateway_unavailable"
    elif "conflict" in text:
        message = "binding_conflict"
    elif "loopback" in text:
        message = "loopback_binding_unavailable"
    elif "effective" in text and "route" in text:
        message = "effective_route_unavailable"
    record = {"schema": "underlay.profile-context-error.v1",
            "phase": _CONTEXT_PHASE if _CONTEXT_PHASE in CONTEXT_PHASES else "configuration",
            "operation": _CONTEXT_OPERATION if _CONTEXT_OPERATION in CONTEXT_OPERATIONS else "verify",
            "error_class": error_class, "message": message, "exit_status": 1}
    nested = validated_nested(getattr(error, "nested", None))
    if nested is not None:
        record["nested"] = nested
    return record


def validated_context_record(value: object) -> dict | None:
    if not isinstance(value, dict) or value.get("schema") != "underlay.profile-context-error.v1":
        return None
    fields = {"phase": CONTEXT_PHASES, "operation": CONTEXT_OPERATIONS,
              "error_class": CONTEXT_CLASSES, "message": CONTEXT_MESSAGES}
    if any(not isinstance(value.get(key), str) or value[key] not in allowed for key, allowed in fields.items()):
        return None
    code = value.get("exit_status")
    if code is not None and (type(code) is not int or not -255 <= code <= 255):
        return None
    record = {"schema": value["schema"], **{key: value[key] for key in fields}, "exit_status": code}
    if "nested" in value:
        nested = validated_nested(value["nested"])
        if nested is None:
            return None
        record["nested"] = nested
    return record


def _cli_failure(error: Exception) -> None:
    if _CONTEXT_ACTION:
        print("UNDERLAY_CONTEXT_ERROR " + json.dumps(context_error_record(error), separators=(",", ":")), file=sys.stderr, flush=True)
    else:
        print(f"PROFILE REFUSED/FAILED: {error}", file=sys.stderr, flush=True)
# END context-only diagnostic helpers


def verify_unchanged(identity: BinaryIdentity) -> None:
    current = verify_binary(identity.source, identity.binary)
    if current != identity:
        raise ProfileError("qualified Effigy source or binary identity changed after admission; no further action taken")


def _safe_repo_path(repo: Path, path: Path) -> Path:
    resolved = path.resolve(strict=False)
    if resolved != repo and repo not in resolved.parents:
        raise ProfileError(f"profile-owned path escapes the consumer checkout: {path}")
    current = repo
    for part in resolved.relative_to(repo).parts:
        current = current / part
        if current.is_symlink():
            raise ProfileError(f"profile-owned path contains a symlink; refusing to follow it: {current}")
    return resolved


def _ensure_private_root(repo: Path, profile: str) -> Path:
    root = _safe_repo_path(repo, repo / ".effigy" / "runtime" / "dev-profiles" / profile / "gateway")
    for path in (repo / ".effigy", repo / ".effigy" / "runtime", root.parent, root):
        if path.exists():
            if not path.is_dir() or path.is_symlink():
                raise ProfileError(f"profile state path is not a real directory: {path}")
        else:
            path.mkdir(mode=0o700, parents=True)
            if path == root:
                path.chmod(0o700)
    metadata = root.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ProfileError(f"private gateway root must be caller-owned mode 0700: {root}")
    return root


def _prepare_silo_override(repo: Path) -> None:
    planned: list[tuple[Path, dict[str, bytes]]] = []
    for alias in ("silo", "silo-mc"):
        source = Path(__file__).resolve().parent / "catalog" / alias
        target = _safe_repo_path(repo, repo / "infra" / "dev" / "catalog" / alias)
        expected_names = ("service.toml", "compose.fragment.yml")
        expected = {name: (source / name).read_bytes() for name in expected_names}

        if target.exists():
            if not target.is_dir() or target.is_symlink():
                raise ProfileError(f"project-local {alias} catalog override is not a directory: {target}")
            actual_names = {entry.name for entry in target.iterdir()}
            if actual_names != set(expected_names):
                raise ProfileError(
                    f"existing project-local {alias} catalog differs from the bundle-owned profile override: {target}; "
                    "preserve it and resolve the conflict explicitly"
                )
            for name, contents in expected.items():
                item = target / name
                if item.is_symlink() or not item.is_file() or item.read_bytes() != contents:
                    raise ProfileError(
                        f"existing project-local {alias} catalog file differs from the bundle override: {item}; "
                        "preserve it and resolve the conflict explicitly"
                )
            continue

        if target.parent.exists() and (not target.parent.is_dir() or target.parent.is_symlink()):
            raise ProfileError(f"project-local catalog parent is not a real directory: {target.parent}")
        if target.parent.exists() and repo not in target.parent.resolve().parents:
            raise ProfileError(f"project-local {alias} catalog destination is not confined to the consumer checkout")
        planned.append((target, expected))

    for target, expected in planned:
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if target.parent.is_symlink() or repo not in target.parent.resolve().parents:
            raise ProfileError(f"project-local catalog destination is not confined to the consumer checkout")
        target.mkdir(mode=0o755)
        for name, contents in expected.items():
            path = target / name
            with path.open("xb") as handle:
                handle.write(contents)
            path.chmod(0o644)


def _run_process(
    identity: BinaryIdentity,
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    capture: bool = True,
    emit_stdout: bool = True,
    emit_stderr: bool = True,
) -> subprocess.CompletedProcess[str]:
    verify_unchanged(identity)
    if not argv or argv[0] != identity.binary or not Path(argv[0]).is_absolute():
        raise ProfileError("nested Effigy invocation is not bound to the verified absolute binary")
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            start_new_session=True,
        )
    except OSError as error:
        # BEGIN nested context diagnostic
        if _CONTEXT_ACTION:
            raise nested_failure("unknown", "unclassified", "spawn", None) from None
        # END nested context diagnostic
        raise ProfileError(f"could not start the verified Effigy binary: {error}") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _stop_owned_process_group(process.pid)
        stdout, stderr = process.communicate()
        # BEGIN nested context diagnostic
        if _CONTEXT_ACTION:
            raise nested_failure("unknown", "unclassified", "timeout", process.returncode) from None
        # END nested context diagnostic
        raise ProfileError(f"Effigy command exceeded its {timeout}-second bound") from error
    except KeyboardInterrupt:
        _signal_owned_process_group(process.pid, signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            _stop_owned_process_group(process.pid)
            stdout, stderr = process.communicate()
        raise
    result = subprocess.CompletedProcess(argv, process.returncode, stdout or "", stderr or "")
    if capture:
        if result.stdout:
            if emit_stdout:
                print(result.stdout.rstrip(), flush=True)
        if result.returncode and result.stderr and emit_stderr:
            print(result.stderr.rstrip(), file=sys.stderr, flush=True)
    if result.returncode != 0:
        # BEGIN nested context diagnostic
        if _CONTEXT_ACTION and not emit_stdout:
            return result
        # END nested context diagnostic
        detail = _safe_error(result.stderr or result.stdout)
        raise ProfileError(f"Effigy command failed ({result.returncode}): {' '.join(argv[1:])}{detail}")
    return result


def _signal_owned_process_group(pid: int, signum: int) -> None:
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def _stop_owned_process_group(pid: int) -> None:
    _signal_owned_process_group(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    _signal_owned_process_group(pid, signal.SIGKILL)


def _safe_error(value: str) -> str:
    value = value.replace(SILO_PASSWORD, "[REDACTED]")
    value = re.sub(r"(?i)(password|secret|token)(\s*[:=]\s*)[^,;\s]+", r"\1\2[REDACTED]", value)
    useful = [line.strip() for line in value.splitlines() if re.search(r"(?i)error|failed|invalid|missing|required", line)]
    return "; " + " | ".join(useful)[-800:] if useful else ""


def _json_command(
    identity: BinaryIdentity,
    repo: Path,
    env: dict[str, str],
    *args: str,
    timeout: int = 180,
) -> dict:
    command_env = dict(env)
    command_env.pop("EFFIGY_INTERNAL_SUPPRESS_HEADER", None)
    result = _run_process(
        identity,
        [identity.binary, "--repo", str(repo), "--json", *args],
        cwd=repo,
        env=command_env,
        timeout=timeout,
        emit_stdout=False,
        emit_stderr=not _CONTEXT_ACTION,
    )
    # BEGIN nested context diagnostic
    if _CONTEXT_ACTION:
        return context_json_result(result)
    # END nested context diagnostic
    try:
        envelope = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise ProfileError(f"Effigy did not return JSON for {' '.join(args)}") from error
    if envelope.get("ok") is not True:
        error = envelope.get("error") or {}
        raise ProfileError(str(error.get("message") or f"Effigy returned a negative result for {' '.join(args)}"))
    result_value = envelope.get("result")
    return result_value if isinstance(result_value, dict) else {}


def _gateway_json(
    identity: BinaryIdentity,
    repo: Path,
    env: dict[str, str],
    *args: str,
    timeout: int = 180,
) -> dict:
    gateway_env = dict(env)
    gateway_env.pop("EFFIGY_INTERNAL_SUPPRESS_HEADER", None)
    result = _run_process(
        identity,
        [identity.binary, "--json", "gateway", *args],
        cwd=repo,
        env=gateway_env,
        timeout=timeout,
        emit_stdout=False,
        emit_stderr=not _CONTEXT_ACTION,
    )
    try:
        envelope = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise ProfileError(f"Effigy did not return JSON for gateway {' '.join(args)}") from error
    if envelope.get("ok") is not True:
        error = envelope.get("error") or {}
        raise ProfileError(
            str(error.get("message") or f"Effigy returned a negative gateway result for {' '.join(args)}")
        )
    result_value = envelope.get("result")
    while (
        isinstance(result_value, dict)
        and "https_addr" not in result_value
        and isinstance(result_value.get("result"), dict)
    ):
        result_value = result_value["result"]
    return result_value if isinstance(result_value, dict) else {}


def _compose_loopback_port_bindings(repo: Path, status: dict) -> list[tuple[str, int, int]]:
    compose_value = status.get("compose_file")
    if not isinstance(compose_value, str) or not compose_value:
        return []
    compose_candidate = Path(compose_value)
    if not compose_candidate.is_absolute():
        compose_candidate = repo / compose_candidate
    try:
        compose_path = _safe_repo_path(repo, compose_candidate)
        lines = compose_path.read_text(encoding="utf-8").splitlines()
    except (OSError, ProfileError):
        return []

    service_header = re.compile(r"^  ([A-Za-z0-9_.-]+):$")
    port_mapping = re.compile(r"^\s*-\s*['\"]?127\.0\.0\.1:(\d+):(\d+)(?:/(?:tcp|udp))?['\"]?\s*$")
    service_starts = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := service_header.fullmatch(line))
    ]
    bindings: list[tuple[str, int, int]] = []
    for service_index, (start, service_name) in enumerate(service_starts):
        end = service_starts[service_index + 1][0] if service_index + 1 < len(service_starts) else len(lines)
        in_ports = False
        for line in lines[start + 1:end]:
            indentation = len(line) - len(line.lstrip(" "))
            if indentation == 4 and line.strip() == "ports:":
                in_ports = True
                continue
            if in_ports and indentation == 4 and line.lstrip().startswith("-"):
                match = port_mapping.fullmatch(line)
                if match:
                    bindings.append((service_name, int(match.group(1)), int(match.group(2))))
                continue
            if in_ports and line.strip() and indentation <= 4:
                in_ports = False
    return bindings


def _service_port(
    status: dict,
    service_name: str,
    target_port: int,
    repo: Path,
    *,
    compose_bindings: list[tuple[str, int, int]] | None = None,
) -> int:
    target_pattern = re.compile(r"->" + str(target_port) + r"(?:/(?:tcp|udp))?$")
    explicit_loopback_pattern = re.compile(
        r"127\.0\.0\.1:(\d+)->" + str(target_port) + r"(?:/(?:tcp|udp))?$"
    )
    unqualified_pattern = re.compile(r"(\d+)->" + str(target_port) + r"(?:/(?:tcp|udp))?$")
    service_rows = status.get("services") or []
    matching_services = [service for service in service_rows if service.get("name") == service_name]
    bindings = (
        compose_bindings
        if compose_bindings is not None
        else _compose_loopback_port_bindings(repo, status)
    )
    host_ports: list[int] = []
    explicit_loopback_ports: list[int] = []
    target_mappings: list[str] = []
    for service in matching_services:
        for mapping in service.get("ports") or []:
            value = str(mapping)
            if not target_pattern.search(value):
                continue
            target_mappings.append(value)
            explicit_loopback = explicit_loopback_pattern.fullmatch(value)
            unqualified = unqualified_pattern.fullmatch(value)
            match = explicit_loopback or unqualified
            if match:
                host_port = int(match.group(1))
                host_ports.append(host_port)
                if explicit_loopback:
                    explicit_loopback_ports.append(host_port)
    if target_mappings and len(host_ports) != len(target_mappings):
        raise ProfileError(f"Effigy reported a non-loopback service mapping for {service_name}:{target_port}")
    if host_ports:
        if len(set(host_ports)) != 1:
            raise ProfileError(f"Effigy reported conflicting host ports for {service_name}:{target_port}")
        host_port = host_ports[0]
        allocation_pattern = re.compile(r"(?:127\.0\.0\.1:)?(\d+):(\d+)(?:/(?:tcp|udp))?$")
        allocations = [
            int(match.group(1))
            for mapping in status.get("ports") or []
            if (match := allocation_pattern.fullmatch(str(mapping)))
            and int(match.group(2)) == target_port
        ]
        if allocations and allocations != [host_port]:
            raise ProfileError(
                f"Effigy service mapping conflicts with its status allocation for {service_name}:{target_port} "
                f"(reported={target_mappings!r}, allocations={allocations!r})"
            )
        if host_port > 0 and explicit_loopback_ports == host_ports:
            return host_port
        service_bindings = [
            port for service, port, target in bindings
            if service == service_name and target == target_port
        ]
        if host_port > 0 and service_bindings == [host_port]:
            return host_port
        raise ProfileError(
            f"Effigy service mapping is not a confirmed loopback port for {service_name}:{target_port} "
            f"(reported={target_mappings!r}, compose_bindings={service_bindings!r}, "
            f"compose_file={status.get('compose_file')!r})"
        )

    # During container up, Effigy launches managed host processes before its
    # status rows are populated. Resolve only a unique published allocation,
    # then cross-check the exact service and loopback binding in generated
    # Compose instead of guessing from list order or a catalog default.
    allocation_pattern = re.compile(r"(?:127\.0\.0\.1:)?(\d+):(\d+)(?:/(?:tcp|udp))?$")
    allocations = [
        int(match.group(1))
        for mapping in status.get("ports") or []
        if (match := allocation_pattern.fullmatch(str(mapping)))
        and int(match.group(2)) == target_port
    ]
    target_bindings = [(service, port) for service, port, target in bindings if target == target_port]
    if len(target_bindings) == 1 and target_bindings[0][0] == service_name:
        _, host_port = target_bindings[0]
        if host_port > 0 and (not allocations or allocations == [host_port]):
            return host_port
    raise ProfileError(
        f"Effigy did not report an unambiguous loopback host port for {service_name}:{target_port} "
        f"(status_ports={status.get('ports')!r}, compose_file={status.get('compose_file')!r}, "
        f"compose_target_bindings={target_bindings!r})"
    )
    for service in status.get("services") or []:
        if service.get("name") != service_name:
            continue
        for mapping in service.get("ports") or []:
            match = mapping_pattern.fullmatch(str(mapping))
            if match:
                return int(match.group(1))
    raise ProfileError(f"Effigy did not report a loopback host port for {service_name}:{target_port}")


def profile_for_containers(service_container: str, host_container: str) -> str:
    for profile, (expected_service, expected_host) in PROFILE_CONTAINERS.items():
        if (service_container, host_container) == (expected_service, expected_host):
            return profile
    raise ProfileError(
        f"unsupported managed profile containers {service_container!r}/{host_container!r}"
    )


def profile_context(identity: BinaryIdentity, repo: Path, env: dict[str, str], container: str) -> dict:
    _context_mark("configuration", "private-root")
    private_root = env.get("EFFIGY_GATEWAY_PRIVATE_STATE_ROOT")
    if not private_root:
        raise ProfileError("private gateway state root was not provided to the profile child")
    _context_mark("service-status", container + ".status")
    status = _json_command(identity, repo, env, "container", container, "status")
    # `container hosts` may render another container composition and refresh
    # Effigy's generated Compose snapshot. Keep the exact service bindings that
    # accompanied this status response for any unqualified port mappings.
    _context_mark("compose-bindings", "compose")
    compose_bindings = _compose_loopback_port_bindings(repo, status)
    host_container = env.get("EFFIGY_PROFILE_HOST_CONTAINER_NAME", container)
    host_results = [
        (_context_mark("host-inventory", name + ".hosts"),
         _json_command(identity, repo, env, "container", name, "hosts"))[1]
        for name in dict.fromkeys((container, host_container))
    ]
    # Container-scoped hosts contains service routes but can omit app domains
    # owned by managed host listeners until they have passed readiness. The
    # checkout's default host map supplies their collision-free effective
    # names; the managed listener still owns publication of those routes.
    _context_mark("host-inventory", "default.hosts")
    host_results.append(_json_command(identity, repo, env, "container", "hosts"))
    _context_mark("gateway-status", "gateway.status")
    gateway = _gateway_json(
        identity,
        repo,
        env,
        "status",
        "--private-state-root",
        private_root,
    )
    _context_mark("gateway-port", "gateway.https")
    https_port = _gateway_https_port(gateway)

    _context_mark("route-validation", "routes")
    declared_names = {
        "api": env.get("EFFIGY_PROFILE_API_DECLARED", ""),
        "front": env.get("EFFIGY_PROFILE_FRONT_DECLARED", ""),
        "admin": env.get("EFFIGY_PROFILE_ADMIN_DECLARED", ""),
        "s3": env.get("EFFIGY_PROFILE_S3_DECLARED", ""),
        "dbgate": env.get("EFFIGY_PROFILE_DBGATE_DECLARED", ""),
        "mailpit": env.get("EFFIGY_PROFILE_MAILPIT_DECLARED", ""),
        "silo": env.get("EFFIGY_PROFILE_SILO_DECLARED", ""),
    }
    routes: dict[str, str] = {}
    for hosts in host_results:
        for route in hosts.get("routes") or []:
            for name, declared in declared_names.items():
                if declared and route.get("declared") == declared:
                    effective = route.get("effective")
                    if not isinstance(effective, str) or not effective:
                        raise ProfileError(f"Effigy returned no effective hostname for route {name}")
                    if name in routes and routes[name] != effective:
                        raise ProfileError(f"Effigy returned conflicting hostnames for route {name}")
                    routes[name] = effective
    missing_routes = {name for name, domain in declared_names.items() if domain and name not in routes}
    if missing_routes:
        raise ProfileError(f"Effigy did not report effective profile routes: {sorted(missing_routes)}")

    ports = {
        "postgres": (_context_mark("service-port", "postgres"), _service_port(status, "postgres", 5432, repo, compose_bindings=compose_bindings))[1],
        "smtp": (_context_mark("service-port", "smtp"), _service_port(status, "mailpit", 1025, repo, compose_bindings=compose_bindings))[1],
        "mailpit_http": (_context_mark("service-port", "mailpit_http"), _service_port(status, "mailpit", 8025, repo, compose_bindings=compose_bindings))[1],
        "silo": (_context_mark("service-port", "silo"), _service_port(status, "silo", 9000, repo, compose_bindings=compose_bindings))[1],
        "silo_console": (_context_mark("service-port", "silo_console"), _service_port(status, "silo", 9001, repo, compose_bindings=compose_bindings))[1],
        "dbgate": (_context_mark("service-port", "dbgate"), _service_port(status, "dbgate", 3000, repo, compose_bindings=compose_bindings))[1],
    }
    return {"https_port": https_port, "routes": routes, "ports": ports, "status": status}


def _public_url(domain: str, port: int) -> str:
    return f"https://{domain}" if port == 443 else f"https://{domain}:{port}"


def _gateway_https_port(status: dict) -> int:
    address = status.get("https_addr")
    if not isinstance(address, str) or not address.startswith("127.0.0.1:"):
        raise ProfileError(
            "private gateway status has no loopback HTTPS bind address "
            f"(schema={status.get('schema')!r}, keys={sorted(status)!r}, "
            f"private={status.get('private')!r}, running={status.get('running')!r}, https_addr={address!r})"
        )
    try:
        port = int(address.rsplit(":", 1)[1])
    except ValueError as error:
        raise ProfileError(f"private gateway reported an invalid HTTPS bind address: {address!r}") from error
    if not 1 <= port <= 65535:
        raise ProfileError(f"private gateway HTTPS port is outside the TCP range: {address!r}")
    if status.get("private") is not True or status.get("running") is not True:
        raise ProfileError(
            "private gateway is not running on its owned HTTPS listener "
            f"(private={status.get('private')!r}, running={status.get('running')!r}, https_addr={address!r})"
        )
    return port


def profile_environment(context: dict, env: dict[str, str]) -> dict[str, str]:
    values = dict(env)
    ports = context["ports"]
    routes = context["routes"]
    database = env.get("EFFIGY_PROFILE_DATABASE_NAME", "")
    if database:
        password = env.get("EFFIGY_PROFILE_DATABASE_PASSWORD", "secret")
        values["DATABASE_URL"] = (
            f"postgres://postgres:{password}@127.0.0.1:{ports['postgres']}/{database}"
        )
    values.update(
        {
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": str(ports["smtp"]),
            "MAILPIT_HOST": "127.0.0.1",
            "MAILPIT_SMTP_PORT": str(ports["smtp"]),
            "MAILPIT_HTTP_PORT": str(ports["mailpit_http"]),
            "ACME_S3_ENDPOINT": f"http://127.0.0.1:{ports['silo']}",
            "ACME_S3_BUCKET": env.get("EFFIGY_PROFILE_SILO_BUCKET", "acme-media"),
            "ACME_S3_PUBLIC_URL_BASE": _public_url(routes["s3"], context["https_port"]),
            "EFFIGY_PROFILE_SILO": "true",
            "AWS_ACCESS_KEY_ID": SILO_USER,
            "AWS_SECRET_ACCESS_KEY": SILO_PASSWORD,
            "AWS_EC2_METADATA_DISABLED": "true",
            "PUBLIC_HOST": routes["api"],
            "PUBLIC_SCHEME": "https",
            "PUBLIC_PORT": str(context["https_port"]),
            "COOKIE_DOMAIN": "." + routes["api"].split(".", 1)[1],
            "CORS_ORIGINS": ",".join(
                _public_url(routes[role], context["https_port"])
                for role in ("front", "admin")
            ),
        }
    )
    for role in ("api", "front", "admin", "s3", "dbgate", "mailpit", "silo"):
        if role in routes:
            values[f"EFFIGY_PROFILE_{role.upper()}_PUBLIC_URL"] = _public_url(
                routes[role], context["https_port"]
            )
    values["EFFIGY_PROFILE_GATEWAY_HTTPS_PORT"] = str(context["https_port"])
    return values


def _private_gateway_status(identity: BinaryIdentity, repo: Path, env: dict[str, str], root: Path) -> dict:
    if not root.exists():
        return {"running": False, "routes": []}
    return _gateway_json(
        identity,
        repo,
        env,
        "status",
        "--private-state-root",
        str(root),
    )


def _assert_stopped(identity: BinaryIdentity, repo: Path, env: dict[str, str], container: str) -> None:
    status = _json_command(identity, repo, env, "container", container, "status")
    active = [
        str(service.get("name"))
        for service in status.get("services") or []
        if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}
    ]
    if active:
        raise ProfileError(f"{container} already has active services; inspect the exact profile before retrying: {active}")
    state_root = repo / ".effigy" / "runtime" / "host-processes" / container
    if state_root.exists():
        active_states = []
        for state_path in state_root.rglob("*.listener.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                active_states.append(str(state_path))
                continue
            if state.get("status") != "stopped" or state.get("route_owner") is not None:
                active_states.append(f"{state_path.name}:{state.get('status') or 'unknown'}")
        if active_states:
            raise ProfileError(f"{container} has recorded host listener ownership; inspect before starting: {active_states}")


def _assert_gateway_idle(status: dict) -> None:
    active_routes = status.get("routes") or []
    if status.get("running") or active_routes:
        raise ProfileError("the private gateway root is already active; inspect its exact routes before starting")


def _gateway_start(identity: BinaryIdentity, repo: Path, env: dict[str, str], root: Path) -> None:
    _gateway_json(
        identity,
        repo,
        env,
        "setup-tls",
        "--private-state-root",
        str(root),
        timeout=180,
    )
    gateway_status = _gateway_json(
        identity,
        repo,
        env,
        "up",
        "--dns-addr",
        "127.0.0.1:0",
        "--proxy-addr",
        "127.0.0.1:0",
        "--https-addr",
        "127.0.0.1:0",
        "--private-state-root",
        str(root),
        timeout=300,
    )
    deadline = time.monotonic() + 15
    while True:
        try:
            _gateway_https_port(gateway_status)
            return
        except ProfileError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
            gateway_status = _private_gateway_status(identity, repo, env, root)


def _gateway_down(identity: BinaryIdentity, repo: Path, env: dict[str, str], root: Path) -> None:
    if not root.exists():
        return
    status = _private_gateway_status(identity, repo, env, root)
    if status.get("routes"):
        raise ProfileError("private gateway still has routes after container down; route ownership remains held")
    if status.get("running"):
        _gateway_json(
            identity,
            repo,
            env,
            "down",
            "--private-state-root",
            str(root),
            timeout=180,
        )
    final = _private_gateway_status(identity, repo, env, root)
    if final.get("running") or final.get("routes"):
        raise ProfileError("private gateway did not report stopped with an empty route set")


def _container_up(identity: BinaryIdentity, repo: Path, env: dict[str, str], container: str) -> dict:
    return _json_command(
        identity,
        repo,
        env,
        "container",
        container,
        "up",
        "--detach",
        timeout=5400,
    )


def _container_down(identity: BinaryIdentity, repo: Path, env: dict[str, str], container: str) -> None:
    _json_command(identity, repo, env, "container", container, "down", timeout=900)
    status = _json_command(identity, repo, env, "container", container, "status")
    active = [
        str(service.get("name"))
        for service in status.get("services") or []
        if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}
    ]
    if active:
        raise ProfileError(f"{container} services remain active after down: {active}")
    state_root = _safe_repo_path(repo, repo / ".effigy" / "runtime" / "host-processes" / container)
    if state_root.exists():
        held = []
        for state_path in state_root.rglob("*.listener.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                held.append(f"{state_path.name}:unreadable")
                continue
            status = state.get("status")
            if status not in {"stopped", "failed"} or state.get("route_owner") is not None:
                held.append(f"{state_path.name}:{status or 'missing-owner-state'}")
                continue
            if status == "failed" and any(
                state.get(field) is not None
                for field in ("internal_url", "public_url", "child_pid", "listener_pid")
            ):
                held.append(f"{state_path.name}:failed-with-live-owner-fields")
        if held:
            raise ProfileError(f"{container} managed host listeners remain uncertain after down: {held}")


_LAUNCHER_FIELDS = ('EFFIGY_PROFILE_SILO_BUCKET', *(
    'EFFIGY_PROFILE_'+role+'_DECLARED'
    for role in ('API','FRONT','ADMIN','S3','DBGATE','MAILPIT','SILO')))


def _silo_journal(repo: Path, container: str):
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,63}',container):
        raise ProfileError('Silo bootstrap container refused')
    root=_safe_repo_path(repo,repo/'.effigy'/'runtime'/'dev-profiles'/container)
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=root/'silo-bootstrap.jsonl'
    class Journal:
        def append(self,event,**record):
            flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW
            fd=os.open(path,flags,0o600)
            try:
                info=os.fstat(fd)
                if info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or not stat.S_ISREG(info.st_mode):
                    raise ProfileError('Silo bootstrap journal boundary refused')
                data=(json.dumps({'event':event,**record},separators=(',',':'))+'\n').encode()
                if info.st_size+len(data)>131072:raise ProfileError('Silo bootstrap journal bound refused')
                if os.write(fd,data)!=len(data):raise ProfileError('Silo bootstrap journal write refused')
            finally:os.close(fd)
    return Journal()


def _input_shape(name, value):
    if not isinstance(value,str):return False
    if name=='EFFIGY_PROFILE_SILO_BUCKET':
        return re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',value) is not None
    return (0<len(value)<=253 and all(
        re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label)
        for label in value.split('.')))


def _launcher_source_refused(journal,reason):
    for name in _LAUNCHER_FIELDS:
        journal.append('launcher_input_agreement',field=name,source_state='unavailable',
                       source_present=None,source_string_type=None,source_shape_agreement=None,agreement=False)
    journal.append('launcher_source_refusal',reason=reason)
    raise ProfileError('Profile launcher input source refused') from None


def _validate_launcher_inputs(identity, repo, env, profile):
    container=PROFILE_CONTAINERS[profile][0]
    journal=_silo_journal(repo,container)
    valid=True
    for name in _LAUNCHER_FIELDS:
        value=env.get(name);shape=_input_shape(name,value)
        journal.append('launcher_input',field=name,present=name in env,
                       string_type=isinstance(value,str),shape_agreement=shape)
        valid=valid and shape
    if not valid:raise ProfileError('Profile launcher input contract refused')
    # Independently compare the launcher with the current composed application
    # declarations. Config inspection has no backend/service/gateway effects.
    path='containers.'+container+'.host_processes'
    verify_unchanged(identity)
    try:
        capture=silo_client.bounded_run([identity.binary,'--repo',str(repo),'--json',
                                       'config','--inspect','--path',path],cwd=repo,env=env,timeout=120)
    except (OSError,subprocess.SubprocessError):
        _launcher_source_refused(journal,'capture_unavailable')
    journal.append('launcher_source_capture',outcome=capture['outcome'],exit=capture['exit'],
                   stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'])
    try:
        if capture['outcome']!='complete' or capture['exit']:raise ValueError()
        envelope=silo_client.strict_json(capture['stdout'].decode())
        result=envelope['result'];selected=result['selected_value']
        if (envelope.get('schema')!='effigy.command.v1' or envelope.get('ok') is not True
                or result.get('schema')!='effigy.config.v1' or result.get('ok') is not True
                or result.get('selected_path')!=path or selected.get('path')!=path):raise ValueError()
        processes=selected['value']
        if not isinstance(processes,list) or not all(isinstance(p,dict) and isinstance(p.get('name'),str) for p in processes):raise ValueError()
        apps=[p for p in processes if isinstance(p,dict) and p.get('name') in ('api','front','admin')]
        if len(apps)!=3 or {p['name'] for p in apps}!={'api','front','admin'}:raise ValueError()
        bindings=[p.get('env') for p in apps if p['name']=='api']
        if not all(isinstance(b,dict) for b in bindings):raise ValueError()
    except (KeyError,TypeError,ValueError,UnicodeError,AttributeError):
        _launcher_source_refused(journal,'typed_declarations_unavailable')
    valid=True
    for name in _LAUNCHER_FIELDS:
        values=[b.get(name) for b in bindings]
        source_valid=all(_input_shape(name,v) for v in values)
        agreement=source_valid and all(v==env[name] for v in values)
        journal.append('launcher_input_agreement',field=name,source_present=all(name in b for b in bindings),
                       source_string_type=all(isinstance(v,str) for v in values),
                       source_shape_agreement=source_valid,agreement=agreement)
        valid=valid and agreement
    if not valid:raise ProfileError('Profile launcher input agreement refused')


def _bootstrap_silo(
    identity: BinaryIdentity,
    repo: Path,
    env: dict[str, str],
    container: str,
    context: dict,
) -> None:
    journal=_silo_journal(repo,container)
    bucket=env.get('EFFIGY_PROFILE_SILO_BUCKET')
    journal.append('bootstrap_input',field='EFFIGY_PROFILE_SILO_BUCKET',present='EFFIGY_PROFILE_SILO_BUCKET' in env,
                   string_type=isinstance(bucket,str),shape_agreement=_input_shape('EFFIGY_PROFILE_SILO_BUCKET',bucket))
    routes=context.get('routes') if isinstance(context,dict) else None
    values={name:routes.get(name) if isinstance(routes,dict) else None for name in ('front','admin')}
    port=context.get('https_port') if isinstance(context,dict) else None
    valid=_input_shape('EFFIGY_PROFILE_SILO_BUCKET',bucket)
    for name,value in values.items():
        shape=_input_shape('EFFIGY_PROFILE_'+name.upper()+'_DECLARED',value)
        journal.append('bootstrap_input',field=name,present=name in routes if isinstance(routes,dict) else None,
                       string_type=isinstance(value,str),shape_agreement=shape)
        valid=valid and shape
    port_valid=type(port) is int and 1<=port<=65535
    journal.append('bootstrap_input',field='https_port',present='https_port' in context if isinstance(context,dict) else None,
                   integer_type=type(port) is int,shape_agreement=port_valid)
    if not valid or not port_valid:raise ProfileError('Silo bootstrap input contract refused')
    origins=(_public_url(values['front'],port),_public_url(values['admin'],port))
    cors = "".join(
        (
            "<CORSConfiguration><CORSRule>",
            *(f"<AllowedOrigin>{html.escape(origin, quote=True)}</AllowedOrigin>" for origin in origins),
            "<AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod>",
            "<AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader>",
            "<ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-request-id</ExposeHeader>",
            "<ExposeHeader>x-amz-id-2</ExposeHeader><MaxAgeSeconds>3000</MaxAgeSeconds>",
            "</CORSRule></CORSConfiguration>",
        )
    )
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,63}',container):
        raise ProfileError('Silo bootstrap container refused')
    def call(label,unused,args,timeout):
        verify_unchanged(identity)
        command_env=dict(env);command_env.pop('EFFIGY_INTERNAL_SUPPRESS_HEADER',None)
        # Never use _run_process's argument-bearing failure text or unbounded
        # communicate buffer for credential-bearing finite commands.
        capture=silo_client.bounded_run([identity.binary,'--repo',str(repo),*args],
                                      cwd=repo,env=command_env,timeout=timeout)
        journal.append('host_capture',operation=label,outcome=capture['outcome'],
                       exit=capture['exit'],stdout_bytes=capture['stdout_bytes'],stderr_bytes=capture['stderr_bytes'])
        if capture['outcome']!='complete':raise ValueError('command_capture_'+capture['outcome'])
        return capture['stdout'].decode(),capture['exit']
    def shell(label,command,service='silo_client'):
        try:return silo_client.finite_shell(call,journal,label,command,service,container)
        except Exception:
            raise ProfileError('Silo bootstrap finite stage refused: '+label) from None
    # Readonly guards precede every possible mutation; diagnostic completion
    # never grants semantic acceptance of a false predicate.
    try:
        for service in ('silo','silo_client'):
            silo_client.evaluate_guard(shell,journal,service)
    except Exception:
        raise ProfileError('Silo bootstrap readonly guard refused') from None
    mc=silo_client.mc_command
    shell('client_tools','set -eu; command -v mc >/dev/null; command -v rm >/dev/null')
    try:
        silo_client.alias_projection(shell('alias_set',mc(['alias','set','local','http://silo:9000',SILO_USER,SILO_PASSWORD,
                      '--api','S3v4','--path','auto'],json_output=True)),journal,'alias_set')
        silo_client.alias_projection(shell('alias_list',mc(['alias','list','local'],json_output=True)),journal)
    except Exception:
        raise ProfileError('Silo bootstrap alias configuration refused') from None
    # One native absolute deadline bounds the client's own readonly readiness
    # operation. No infinite shell loop and no repeated remote mutation.
    shell('ready',mc(['ready','local']))
    shell('bucket',mc(['mb','local/'+bucket,'--ignore-existing']))
    shell('anonymous',mc(['anonymous','set','download','local/'+bucket]))
    # Qualified rm is checked before file creation. Noclobber and a fresh nonce
    # give this exact file exclusive ownership; trap only removes that file.
    cors_file='/tmp/underlay-profile-cors-'+secrets.token_hex(16)
    shell('cors',"set -eu; command -v rm >/dev/null; set -C; "+
          'printf %s '+shlex.quote(cors)+' > '+shlex.quote(cors_file)+'; '+
          'trap '+shlex.quote('rm -f '+shlex.quote(cors_file))+' EXIT; '+
          mc(['cors','set','local/'+bucket,cors_file]))


def _check_test_task(env: dict[str, str]) -> tuple[str, int]:
    selector = env.get("UNDERLAY_PROFILE_TEST_TASK", "").strip()
    if not selector:
        raise ProfileError("set profiles.test_task to one bounded Effigy selector before using dev:test")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.:/-]+", selector)
        or selector.startswith(("-", "/"))
        or any(part in {".", ".."} for part in selector.split("/"))
        or selector.split(":", 1)[0].lower() in {"qa", "ci"}
    ):
        raise ProfileError(
            "profiles.test_task must be one focused Effigy selector without shell syntax, arguments or full QA"
        )
    try:
        timeout = int(env.get("UNDERLAY_PROFILE_TEST_TIMEOUT_SECS", "900"))
    except ValueError as error:
        raise ProfileError("profiles.test_timeout_secs must be an integer") from error
    if not 1 <= timeout <= 7200:
        raise ProfileError("profiles.test_timeout_secs must be between 1 and 7200")
    return selector, timeout


def _profile_env(repo: Path, root: Path, env: dict[str, str], profile: str) -> dict[str, str]:
    result = dict(env)
    result["EFFIGY_GATEWAY_PRIVATE_STATE_ROOT"] = str(root)
    result["UNDERLAY_PROFILE_REPO"] = str(repo)
    service_container, host_container = PROFILE_CONTAINERS[profile]
    result["EFFIGY_PROFILE_CONTAINER_NAME"] = service_container
    result["EFFIGY_PROFILE_HOST_CONTAINER_NAME"] = host_container
    return result


def _profile_root(repo: Path, profile: str) -> Path:
    state_name = "hybrid" if profile == "hybrid" else "test"
    return _safe_repo_path(repo, repo / ".effigy" / "runtime" / "dev-profiles" / state_name / "gateway")


def _container_active(status: dict) -> bool:
    return any(
        str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}
        for service in status.get("services") or []
    )


def _assert_profile_services_ready(status: dict, container: str) -> None:
    services = {
        str(item.get("name")): str(item.get("status", "")).lower()
        for item in status.get("services") or []
    }
    required = {"postgres", "dbgate", "mailpit", "silo", "silo_client"}
    missing = sorted(name for name in required if services.get(name) not in {"up", "running"})
    if missing:
        raise ProfileError(f"{container} has active but incomplete/uncertain services: {missing}")


def _assert_profile_listeners_ready(status: dict, container: str) -> None:
    listeners = {
        str(item.get("name")): str(item.get("status", "")).lower()
        for item in status.get("managed_host_listeners") or []
    }
    missing = sorted(name for name in ("api", "front", "admin") if listeners.get(name) != "ready")
    if missing:
        raise ProfileError(f"{container} has active but incomplete/uncertain host listeners: {missing}")


def _assert_profile_ready(status: dict, container: str) -> None:
    _assert_profile_services_ready(status, container)
    _assert_profile_listeners_ready(status, container)


def _scope_owner_key(identity: BinaryIdentity, repo: Path, env: dict[str, str]) -> str:
    scope = _json_command(identity, repo, env, "container", "scope")
    if scope.get("schema") != "effigy.container.scope.v1" or scope.get("ok") is not True:
        raise ProfileError("Effigy returned an unsupported checkout scope identity")
    if scope.get("checkout") != str(repo.resolve()):
        raise ProfileError("Effigy checkout scope identity does not match the admitted consumer checkout")
    details = scope.get("scope")
    if not isinstance(details, dict):
        raise ProfileError("Effigy checkout scope identity is incomplete")

    kind = details.get("kind")
    token = details.get("token")
    if kind == "none" and token is None:
        return repo.name
    if kind in {"worktree", "ephemeral-clone"} and isinstance(token, str):
        if re.fullmatch(r"[0-9a-f]{32}", token):
            return token
    raise ProfileError("Effigy checkout scope identity has an invalid kind or generation token")


def _managed_listener_states(
    identity: BinaryIdentity,
    repo: Path,
    env: dict[str, str],
    container: str,
) -> list[dict]:
    root = _safe_repo_path(
        repo,
        repo / ".effigy" / "runtime" / "host-processes" / container / "effigy",
    )
    owner_key = _scope_owner_key(identity, repo, env)
    states = []
    for name in ("api", "front", "admin"):
        state_path = _safe_repo_path(repo, root / f"{name}.listener.json")
        if not state_path.is_file():
            raise ProfileError(f"{container} managed listener state is missing: {name}")
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ProfileError(f"{container} managed listener state is unreadable: {name}") from error
        expected_owner = f"{owner_key}|{container}|effigy|{name}"
        if state.get("owner") != expected_owner or state.get("status") != "ready":
            raise ProfileError(
                f"{container} managed listener state is not ready for its checkout owner: {name}"
            )
        states.append({"name": name, "status": state["status"], **state})
    return states


def _verified_managed_listeners(
    identity: BinaryIdentity,
    repo: Path,
    env: dict[str, str],
    container: str,
    up_result: dict | None = None,
) -> list[dict]:
    states = _managed_listener_states(identity, repo, env, container)
    _assert_profile_listeners_ready({"managed_host_listeners": states}, container)
    if up_result is None:
        return states

    reported = up_result.get("managed_host_listeners") or []
    _assert_profile_listeners_ready({"managed_host_listeners": reported}, container)
    state_by_name = {item["name"]: item for item in states}
    reported_by_name = {item.get("name"): item for item in reported}
    if set(reported_by_name) != set(state_by_name):
        raise ProfileError(f"{container} startup report does not name the three owned listeners")
    for name, state in state_by_name.items():
        report = reported_by_name[name]
        for field in ("runtime_generation", "generation", "address", "internal_url", "public_url", "route_domain"):
            if report.get(field) != state.get(field):
                raise ProfileError(f"{container} startup report and owned listener state disagree: {name}.{field}")
    return states


def _start_services(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> dict:
    service_container, _ = PROFILE_CONTAINERS[profile]
    root = _profile_root(repo, profile)
    runtime_env = _profile_env(repo, root, env, profile)
    _prepare_silo_override(repo)
    service_status = _json_command(identity, repo, runtime_env, "container", service_container, "status")
    gateway_status = _private_gateway_status(identity, repo, runtime_env, root)
    if _container_active(service_status):
        if not gateway_status.get("running"):
            raise ProfileError(f"{service_container} services are active without their recorded private gateway")
        service_status["managed_host_listeners"] = _verified_managed_listeners(
            identity, repo, runtime_env, service_container
        )
        _assert_profile_ready(service_status, service_container)
        return {"context": profile_context(identity, repo, runtime_env, service_container),
                "status": service_status, "already_running": True}
    if gateway_status.get("running") or gateway_status.get("routes"):
        raise ProfileError("private gateway is active without its exact profile services; inspect before continuing")

    _assert_stopped(identity, repo, runtime_env, service_container)
    _assert_gateway_idle(gateway_status)
    _ensure_private_root(repo, "hybrid" if profile == "hybrid" else "test")
    try:
        _gateway_start(identity, repo, runtime_env, root)
        up = _container_up(identity, repo, runtime_env, service_container)
        status = _json_command(identity, repo, runtime_env, "container", service_container, "status")
        status["managed_host_listeners"] = _verified_managed_listeners(
            identity, repo, runtime_env, service_container, up
        )
        _assert_profile_ready(status, service_container)
        context = profile_context(identity, repo, runtime_env, service_container)
        return {"context": context, "services_up": up, "status": status}
    except BaseException as original:
        try:
            _container_down(identity, repo, runtime_env, service_container)
            _gateway_down(identity, repo, runtime_env, root)
        except BaseException as cleanup_error:
            raise ProfileError(
                f"profile service startup failed and owned cleanup could not be verified; resources are held: "
                f"{cleanup_error}"
            ) from original
        raise


def _start_profile(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> dict:
    _validate_launcher_inputs(identity,repo,env,profile)
    result = _start_services(identity, repo, env, profile)
    context = result["context"]
    if not result.get("already_running"):
        _bootstrap_silo(identity,repo,_profile_env(repo,_profile_root(repo,profile),env,profile),
                        PROFILE_CONTAINERS[profile][0],context)
    print(
        f"PROFILE READY: {profile}; private HTTPS port={context['https_port']}; "
        f"routes={json.dumps(context['routes'], sort_keys=True)}",
        flush=True,
    )
    return context


def _stop_profile(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> None:
    service_container, host_container = PROFILE_CONTAINERS[profile]
    root = _profile_root(repo, profile)
    runtime_env = _profile_env(repo, root, env, profile)
    for container in dict.fromkeys((host_container, service_container)):
        _container_down(identity, repo, runtime_env, container)
    _gateway_down(identity, repo, runtime_env, root)
    print(f"PROFILE STOPPED: {profile}; host listeners, services and private routes are down", flush=True)


def _test_profile(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> int:
    selector, timeout = _check_test_task(env)
    _run_process(
        identity,
        [identity.binary, "--repo", str(repo), selector, "--plan"],
        cwd=repo,
        env=env,
        timeout=30,
        emit_stdout=False,
    )
    context = _start_profile(identity, repo, env, profile)
    root = _profile_root(repo, profile)
    runtime_env = profile_environment(context, _profile_env(repo, root, env, profile))
    action_error: BaseException | None = None
    try:
        print(f"RUN ONE DEV TEST SELECTOR: {selector} (timeout {timeout}s)", flush=True)
        _run_process(
            identity,
            [identity.binary, "--repo", str(repo), selector],
            cwd=repo,
            env=runtime_env,
            timeout=timeout,
            capture=False,
        )
    except BaseException as error:
        action_error = error
    try:
        _stop_profile(identity, repo, env, profile)
    except BaseException as cleanup_error:
        if action_error:
            raise ProfileError(f"test selector failed ({action_error}); owned cleanup is held ({cleanup_error})") from action_error
        raise
    if action_error:
        raise action_error
    print("DEV TEST COMPLETE: one configured selector passed; profile containers and private gateway were stopped", flush=True)
    return 0


def _context(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> dict:
    _context_mark("configuration", "private-root")
    service_container, _ = PROFILE_CONTAINERS[profile]
    root = _profile_root(repo, profile)
    return profile_context(identity, repo, _profile_env(repo, root, env, profile), service_container)


def _status(identity: BinaryIdentity, repo: Path, env: dict[str, str], profile: str) -> dict:
    service_container, host_container = PROFILE_CONTAINERS[profile]
    root = _profile_root(repo, profile)
    runtime_env = _profile_env(repo, root, env, profile)
    services = _json_command(identity, repo, runtime_env, "container", service_container, "status")
    applications = services if host_container == service_container else _json_command(
        identity, repo, runtime_env, "container", host_container, "status"
    )
    gateway = _private_gateway_status(identity, repo, runtime_env, root)
    return {"profile": profile, "service_container": services, "host_container": applications,
            "private_gateway": gateway}


def main(argv: list[str] | None = None) -> int:
    global _CONTEXT_ACTION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "status", "down", "test", "context"))
    parser.add_argument("container", choices=("hybrid", "disposable_test"))
    parser.add_argument("--repo", required=True)
    args = parser.parse_args(argv)
    _CONTEXT_ACTION = args.action == "context"

    env = os.environ.copy()
    identity = verify_binary(
        env.get("UNDERLAY_PROFILE_EFFIGY_SOURCE"),
        env.get("UNDERLAY_PROFILE_EFFIGY_BIN"),
    )
    repo = Path(args.repo).expanduser().resolve(strict=True)
    if not (repo / "effigy.toml").is_file():
        raise ProfileError(f"consumer checkout has no effigy.toml: {repo}")
    _safe_repo_path(repo, repo / ".effigy" / "runtime" / "dev-profiles")

    if args.action == "start":
        _start_profile(identity, repo, env, args.container)
    elif args.action == "status":
        print(json.dumps(_status(identity, repo, env, args.container), indent=2, sort_keys=True))
    elif args.action == "down":
        _stop_profile(identity, repo, env, args.container)
    elif args.action == "test":
        if args.container != "disposable_test":
            raise ProfileError("dev:test must target the disposable_test container")
        return _test_profile(identity, repo, env, args.container)
    else:
        context = _context(identity, repo, env, args.container)
        print(json.dumps(context, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProfileError, subprocess.SubprocessError) as error:
        _cli_failure(error)
        raise SystemExit(1)
    except Exception as error:
        if not _CONTEXT_ACTION:
            raise
        _cli_failure(error)
        raise SystemExit(1)
