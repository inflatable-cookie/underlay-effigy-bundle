#!/usr/bin/env python3
"""Run the private Reference service/app qualification under one Effigy owner."""

from __future__ import annotations

import importlib.util
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import shlex
import signal
import smtplib
import socket
import ssl
import subprocess
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from minio_fixture import IMAGE, install_minio_catalog_override, prepare_source_image
from qualification_runtime import require_effigy_binary


REPO = Path(__file__).resolve().parents[1]
REFERENCE_MODULE_PATH = REPO / "scripts/qualify-reference-profiles.py"
SPEC = importlib.util.spec_from_file_location("qualify_reference_profiles", REFERENCE_MODULE_PATH)
REFERENCE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(REFERENCE)


def run(args: list[str], *, cwd: Path | None = None, env: dict[str, str], timeout: int = 600,
        expected: int = 0, print_output: bool = True) -> subprocess.CompletedProcess[str]:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    print(f"EXIT: {result.returncode}", flush=True)
    if print_output:
        if result.stdout.strip():
            print(result.stdout.rstrip(), flush=True)
        if result.stderr.strip():
            print(result.stderr.rstrip(), flush=True)
    else:
        print(f"OUTPUT: captured stdout={len(result.stdout)} bytes stderr={len(result.stderr)} bytes", flush=True)
    if result.returncode != expected:
        detail = safe_effigy_error(result.stdout) or safe_effigy_error(result.stderr)
        suffix = f"; {detail}" if detail else ""
        raise RuntimeError(f"expected exit {expected}, got {result.returncode}: {' '.join(args)}{suffix}")
    return result


def safe_effigy_error(stdout: str) -> str:
    """Retain a bounded Effigy error message without fixture credentials."""
    try:
        envelope = json.loads(stdout)
    except (TypeError, ValueError):
        envelope = None
    error = envelope.get("error") if isinstance(envelope, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    is_json_error = isinstance(message, str)
    if not is_json_error:
        message = stdout
    message = message.replace("qualification-local-only", "[REDACTED]")
    message = message.replace("minioadmin", "[REDACTED]")
    message = re.sub(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)", r"\1[REDACTED]\2", message)
    message = re.sub(
        r"(?i)(password|secret|token|authorization)(\s*[:=]\s*)[^,;\s]+",
        r"\1\2[REDACTED]",
        message,
    )
    if is_json_error:
        return message[:1200]
    useful = [line.strip() for line in message.splitlines()
              if re.search(r"(?i)error|failed|invalid|missing|required|secret|task .*not defined", line)]
    return " | ".join(useful)[-1000:]


def effigy_json(binary: str, checkout: Path, env: dict[str, str], *args: str,
                timeout: int = 180) -> dict:
    result = run([binary, "--repo", str(checkout), *args], cwd=checkout, env=env,
                 timeout=timeout, print_output=False)
    envelope = json.loads(result.stdout)
    if not envelope.get("ok"):
        detail = safe_effigy_error(result.stdout)
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"Effigy returned a non-ok envelope for {' '.join(args)}{suffix}")
    return envelope.get("result") or {}


def gateway_json(binary: str, env: dict[str, str], gateway_root: Path, *args: str) -> dict:
    result = run([binary, "--json", "gateway", *args, "--private-state-root", str(gateway_root)],
                 env=env, timeout=180, print_output=False)
    envelope = json.loads(result.stdout)
    if not envelope.get("ok"):
        raise RuntimeError(f"Effigy private gateway command failed: {' '.join(args)}")
    return envelope.get("result") or {}


def wait_loopback_service(port: int, service: str, timeout_secs: int = 120) -> dict:
    """Prove a private service is reachable before a host adapter consumes it."""
    deadline = time.monotonic() + timeout_secs
    attempts = 0
    last_result = "not_attempted"
    while time.monotonic() < deadline:
        attempts += 1
        try:
            if service == "minio":
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                connection.request("GET", "/minio/health/ready")
                response = connection.getresponse()
                status = response.status
                response.read()  # Discard the health body; only status is evidence.
                connection.close()
                last_result = f"HTTP {status}"
                if status == 200:
                    return {"service": service, "endpoint": f"127.0.0.1:{port}",
                            "result": last_result, "attempts": attempts}
            elif service == "mailpit":
                with smtplib.SMTP("127.0.0.1", port, timeout=3) as client:
                    status, _ = client.ehlo("qualification.invalid")
                    last_result = f"SMTP EHLO {status}"
                    if 200 <= status < 300:
                        return {"service": service, "endpoint": f"127.0.0.1:{port}",
                                "result": last_result, "attempts": attempts}
            elif service == "postgres":
                with socket.create_connection(("127.0.0.1", port), timeout=3):
                    last_result = "TCP connect succeeded"
                    return {"service": service, "endpoint": f"127.0.0.1:{port}",
                            "result": last_result, "attempts": attempts}
            else:
                raise ValueError(f"unsupported private service readiness check: {service}")
        except (OSError, http.client.HTTPException, smtplib.SMTPException) as error:
            last_result = type(error).__name__
        time.sleep(0.5)
    raise RuntimeError(f"{service} did not become loopback-ready within {timeout_secs}s ({last_result})")


def mktemp_root() -> Path:
    # Keep the fixture under the shared home mount so Colima's guest can read
    # its source-build context, and keep the prefix short for Lima's socket
    # path limit. mktemp creates a unique private root for every run.
    temp_parent = Path.home().resolve(strict=True)
    result = subprocess.run(
        ["mktemp", "-d", str(temp_parent / "ur.XXXXXX")],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
        cwd=temp_parent,
    )
    root = Path(result.stdout.strip()).resolve(strict=True)
    root.chmod(0o700)
    return root


def route_domains(hosts: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for route in hosts.get("routes", []):
        declared = route.get("declared")
        effective = route.get("effective")
        if not isinstance(declared, str) or not isinstance(effective, str):
            continue
        if declared == "acme.test":
            result["front"] = effective
        elif declared == "admin.acme.test":
            result["admin"] = effective
        elif declared == "api.acme.test":
            result["api"] = effective
        elif declared == "s3.acme.test":
            result["s3"] = effective
        elif declared == "minio.acme.test":
            result["minio"] = effective
    missing = {"front", "admin", "api", "s3", "minio"} - set(result)
    if missing:
        raise RuntimeError(f"Effigy host map omitted declared Reference routes: {sorted(missing)}")
    return result


def declared_route_domains(hosts: dict) -> dict[str, str]:
    """Return source declarations; Effigy applies checkout scope to these once."""
    result: dict[str, str] = {}
    for route in hosts.get("routes", []):
        declared = route.get("declared")
        if not isinstance(declared, str):
            continue
        if declared == "acme.test":
            result["front"] = declared
        elif declared == "admin.acme.test":
            result["admin"] = declared
        elif declared == "api.acme.test":
            result["api"] = declared
        elif declared == "s3.acme.test":
            result["s3"] = declared
        elif declared == "minio.acme.test":
            result["minio"] = declared
    missing = {"front", "admin", "api", "s3", "minio"} - set(result)
    if missing:
        raise RuntimeError(f"Effigy host map omitted declared Reference routes: {sorted(missing)}")
    return result


def install_dynamic_loopback_service_ports(effigy: str, checkout: Path, env: dict[str, str]) -> dict[str, str]:
    """Pin fixture services to loopback and let the OS allocate each host port."""
    baselines: dict[str, str] = {}
    for service in ("postgres", "mailpit"):
        run([effigy, "--repo", str(checkout), "service", "extract", service,
             "--dir", "infra/dev/catalog", "--json"], cwd=checkout, env=env, timeout=60,
            print_output=False)
    mappings = {
        "postgres": (("- \"5432:5432\"", "- \"0:5432\""),),
        "mailpit": (
            ('- "{{ smtp_port }}:1025"', '- "0:1025"'),
            ('- "{{ ui_port }}:8025"', '- "0:8025"'),
        ),
    }
    for service, replacements in mappings.items():
        fragment = checkout / "infra/dev/catalog" / service / "compose.fragment.yml"
        raw = fragment.read_text(encoding="utf-8")
        baselines[service] = raw
        for before, after in replacements:
            if before not in raw:
                raise RuntimeError(f"{service} fixture catalog differs from the expected port mapping")
            raw = raw.replace(before, after)
        fragment.write_text(raw, encoding="utf-8")
    print("FIXTURE ONLY: Postgres/Mailpit/MinIO publish OS-assigned ports on 127.0.0.1", flush=True)
    return baselines


def service_host_port_from_up(up_report: dict, compose_text: str, target: int) -> int | None:
    """Use Effigy's allocated port receipt and verify its loopback Compose binding."""
    for mapping in up_report.get("ports", []):
        match = re.fullmatch(r"(\d+):(\d+)(?:/(?:tcp|udp))?", mapping)
        if not match or int(match.group(2)) != target:
            continue
        host_port = int(match.group(1))
        if f"127.0.0.1:{host_port}:{target}" not in compose_text:
            raise RuntimeError(f"Effigy port receipt for container port {target} is not bound to loopback")
        return host_port
    return None


def port_from_loopback_endpoint(endpoints: dict, service: str) -> int | None:
    endpoint = endpoints.get(service)
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", endpoint) if isinstance(endpoint, str) else None
    return int(match.group(1)) if match else None


def restore_default_catalogs(checkout: Path, baselines: dict[str, str]) -> None:
    for service in ("postgres", "mailpit"):
        fragment = checkout / "infra/dev/catalog" / service / "compose.fragment.yml"
        fragment.write_text(baselines[service], encoding="utf-8")
    minio = baselines["minio"]
    original_image = "image: minio/minio:{{ version }}"
    if original_image not in minio:
        raise RuntimeError("saved MinIO catalog baseline lost the pinned published image declaration")
    minio = minio.replace(original_image, f"image: {IMAGE}")
    marker = 'MINIO_ROOT_PASSWORD: "{{ root_password }}"'
    if marker not in minio:
        raise RuntimeError("saved MinIO catalog baseline lacks its credential environment declaration")
    minio = minio.replace(
        marker,
        marker + '\n      MC_HOST_local: "http://{{ root_user }}:{{ root_password }}@127.0.0.1:9000"',
    )
    (checkout / "infra/dev/catalog/minio/compose.fragment.yml").write_text(minio, encoding="utf-8")
    print("FIXTURE ONLY: restored default service ports; only MinIO image/bootstrap override remains", flush=True)


def restore_consumer_defaults(checkout: Path, baseline_files: dict[str, bytes | None]) -> None:
    for relative, contents in baseline_files.items():
        target = checkout / relative
        if checkout.resolve() not in target.resolve().parents:
            raise RuntimeError("default-configuration restoration escaped the disposable Reference checkout")
        if contents is None:
            target.unlink(missing_ok=True)
        else:
            target.write_bytes(contents)
    for app in ("acme-front", "acme-admin"):
        app_root = checkout / "apps" / app
        (app_root / "src/qualification-hooks.server.js").unlink(missing_ok=True)
        route = app_root / "src/routes/__qualification/origin"
        if route.exists():
            if app_root.resolve() not in route.resolve().parents:
                raise RuntimeError("temporary probe route escaped the disposable Reference app")
            shutil.rmtree(route)
        readiness = app_root / "src/routes/__effigy/ready"
        if readiness.exists():
            if app_root.resolve() not in readiness.resolve().parents:
                raise RuntimeError("temporary readiness route escaped the disposable Reference app")
            shutil.rmtree(readiness)


def address_accepts_connection(address: str) -> bool:
    host, separator, port_text = address.rpartition(":")
    if not separator:
        raise RuntimeError(f"managed listener address is malformed: {address}")
    try:
        with socket.create_connection((host, int(port_text)), timeout=1):
            return True
    except OSError:
        return False


def parent_chains(pids: list[int | None]) -> dict[str, list[int]]:
    result = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True,
                            timeout=15, check=True)
    parents: dict[int, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            pid, parent = map(int, fields)
        except ValueError:
            continue
        parents[pid] = parent
    chains: dict[str, list[int]] = {}
    for pid in pids:
        if pid is None:
            continue
        chain = []
        current = pid
        seen = set()
        while current > 0 and current in parents and current not in seen and len(chain) < 16:
            chain.append(current)
            seen.add(current)
            current = parents[current]
        chains[str(pid)] = chain
    return chains


def socket_snapshot(address: str | None) -> dict:
    if not address:
        return {"address": address, "listening_pids": []}
    host, separator, port_text = address.rpartition(":")
    if not separator or not port_text.isdigit():
        raise RuntimeError("cannot inventory a malformed managed listener address")
    result = subprocess.run(["lsof", "-nP", "-iTCP:" + port_text, "-sTCP:LISTEN", "-Fpcn"],
                            capture_output=True, text=True, timeout=15, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError("read-only lsof listener inventory failed")
    processes: list[dict] = []
    current: dict[str, object] | None = None
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            if current:
                processes.append(current)
            try:
                current = {"pid": int(line[1:]), "command": None, "names": []}
            except ValueError:
                current = None
        elif current is not None and line.startswith("c"):
            current["command"] = line[1:]
        elif current is not None and line.startswith("n"):
            current["names"].append(line[1:])
    if current:
        processes.append(current)
    expected_name = f"{host}:{int(port_text)}"
    relevant = [item for item in processes
                if any(name.endswith(expected_name) or name == f"*:{int(port_text)}" for name in item["names"])]
    return {"address": address, "listening_pids": relevant}


def capture_runtime_evidence(checkout: Path, names: list[str], evidence_root: Path,
                             label: str) -> dict:
    runtime_dir = checkout / ".effigy/runtime/host-processes/hybrid/effigy"
    evidence_dir = evidence_root / "runtime-evidence" / label / hashlib.sha256(str(checkout).encode()).hexdigest()[:12]
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {}
    for relative in ("effigy.toml", "config/effigy.toml", "apps/acme-api/crates/api/src/main.rs",
                     "apps/acme-front/svelte.config.js", "apps/acme-admin/svelte.config.js"):
        target = checkout / relative
        files[relative] = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None

    process_rows: list[dict] = []
    ancestry_inputs: list[int | None] = []
    for name in names:
        state_path = runtime_dir / f"{name}.listener.json"
        if not state_path.is_file():
            process_rows.append({"name": name, "state": "missing"})
            continue
        state = json.loads(state_path.read_text(encoding="utf-8"))
        spec_path = runtime_dir / f"{name}.spec.json"
        spec = json.loads(spec_path.read_text(encoding="utf-8")) if spec_path.is_file() else None
        generation = state.get("generation")
        report_path = runtime_dir / f"{name}.{generation}.listener-report.json" if generation else None
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path and report_path.is_file() else None
        log_path = runtime_dir / f"{name}.log"
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
        lifecycle_lines = [line for line in log_text.splitlines()
                           if re.search(r"\[effigy host-process\] (started|exited) `", line)][-40:]
        error_lines = safe_child_error_excerpt(log_text)
        listener_pids = [state.get("supervisor_pid"), state.get("child_pid"), state.get("listener_pid")]
        ancestry_inputs.extend(value for value in listener_pids if isinstance(value, int))
        process_identities = {}
        for role, pid in ("supervisor", state.get("supervisor_pid")), ("child", state.get("child_pid")), ("listener", state.get("listener_pid")):
            if not isinstance(pid, int):
                continue
            observation = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid=,ppid=,lstart="],
                capture_output=True, text=True, timeout=15, check=False,
            )
            process_identities[role] = {
                "pid": pid,
                "ps_exit": observation.returncode,
                "current_pid_parent_start": observation.stdout.strip()[:240] or None,
            }
        process_rows.append({
            "name": name,
            "state": state,
            "spec": ({
                "schema": spec.get("schema"),
                "project_path": spec.get("project_path"),
                "runtime_generation": spec.get("runtime_generation"),
                "cwd": spec.get("cwd"),
                "environment_names": sorted((spec.get("env") or {}).keys()),
                "listener": spec.get("listener"),
                "owner": spec.get("owner"),
                "dependency_names": [dep.get("name") for dep in spec.get("dependencies", [])],
                "listener_state_file": spec.get("listener_state_file"),
                "gateway_root": spec.get("gateway_root"),
            } if spec else None),
            "report": ({"schema": report.get("schema"), "generation": report.get("generation"),
                        "address": report.get("address")} if report else None),
            "process_identities": process_identities,
            "socket": socket_snapshot(state.get("address") or (report or {}).get("address")),
            "log": {"bytes": len(log_text.encode()), "lines": len(log_text.splitlines()),
                    "sha256": hashlib.sha256(log_text.encode()).hexdigest() if log_text else None,
                    "lifecycle_lines": lifecycle_lines,
                    "redacted_error_excerpt": error_lines},
        })
    ancestry = parent_chains(ancestry_inputs)
    capture = {"label": label, "checkout": str(checkout), "config_sha256": files,
               "processes": process_rows, "process_parent_chains": ancestry}
    target = evidence_dir / "managed-host-evidence.json"
    target.write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return {"checkout": str(checkout), "evidence": str(target),
            "listener_names": names, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}


def safe_child_error_excerpt(log_text: str) -> list[str]:
    """Retain bounded error context without credentials, key material, or bodies."""
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        log_text,
        flags=re.DOTALL,
    )
    lines = []
    for line in redacted.splitlines():
        if not re.search(r"(?i)(error|failed|exception|cannot|not found|EADDR|ERR_|denied)", line):
            continue
        line = re.sub(
            r"(?i)([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[=:]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            line,
        )
        line = re.sub(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)", r"\1[REDACTED]\2", line)
        line = re.sub(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]", line)
        lines.append(line[:500])
    return lines[-20:]


def declared_host_processes(checkout: Path) -> list[dict]:
    manifest = (checkout / "effigy.toml").read_text(encoding="utf-8")
    parts = re.split(r"(?m)^\[\[containers\.hybrid\.host_processes\]\]\s*$", manifest)[1:]
    processes = []
    for part in parts:
        block = re.split(r"(?m)^\[\[containers\.hybrid\.host_processes\]\]\s*$", part, maxsplit=1)[0]
        name = re.search(r'(?m)^name\s*=\s*"([A-Za-z][A-Za-z0-9_-]{0,63})"\s*$', block)
        if not name:
            raise RuntimeError("hybrid host-process declaration has no valid name")
        route = re.search(r'(?m)^domain\s*=\s*"([^"\r\n]+)"\s*$', block)
        processes.append({"name": name.group(1), "listener": {"route": {"domain": route.group(1)}} if route else {}})
    return processes


def verify_failed_scope_reconciled(checkout: Path, gateway_root: Path,
                                   env: dict[str, str]) -> dict:
    """Accept cleanup only for recorded failed generations with no owned resource."""
    declarations = declared_host_processes(checkout)
    if not declarations:
        return {"host_process_declarations": 0}
    runtime_dir = checkout / ".effigy/runtime/host-processes/hybrid/effigy"
    checked = []
    absent_owner_fields = (
        "address", "internal_url", "public_url", "route_owner", "child_pid",
        "child_boot_identity", "child_start_identity", "listener_pid",
        "listener_boot_identity", "listener_start_identity",
    )
    for process in declarations:
        name = process.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
            raise RuntimeError("hybrid host-process declaration has an invalid listener name")
        pid_record = runtime_dir / f"{name}.pid"
        if pid_record.exists():
            raise RuntimeError(f"{name} supervisor record remains after Effigy down; ownership is held")
        state_path = runtime_dir / f"{name}.listener.json"
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if state.get("schema") != "effigy.managed.host-listener-state.v1":
                raise RuntimeError(f"{name} listener record has an unsupported schema")
            if state.get("status") not in {"failed", "stopped"}:
                raise RuntimeError(f"{name} listener remains {state.get('status')!r}; ownership is held")
            if any(state.get(field) is not None for field in absent_owner_fields):
                raise RuntimeError(f"{name} failed generation retains listener ownership fields")
            diagnostic = state.get("diagnostic") or {}
            if state.get("status") == "failed":
                required_diagnostic_fields = {
                    "report", "claimed_address", "ownership", "candidates_inspected",
                    "observed_listener_pid", "http_probe", "http_status", "route",
                }
                if set(diagnostic) != required_diagnostic_fields or diagnostic.get("route") != "not_reached":
                    raise RuntimeError(f"{name} failed generation lacks the bounded pre-publication diagnostic")
                ownership = diagnostic.get("ownership")
                if ownership == "exclusive_owner_observed":
                    claim = diagnostic.get("claimed_address")
                    if not isinstance(claim, str):
                        raise RuntimeError(f"{name} failed generation has no bounded claimed listener address")
                    sockets = socket_snapshot(claim)
                    if sockets["listening_pids"] or address_accepts_connection(claim):
                        raise RuntimeError(f"{name} failed generation's claimed listener is still active")
                elif ownership == "not_reached":
                    if diagnostic.get("report") == "accepted":
                        raise RuntimeError(f"{name} accepted a child report without reaching ownership verification")
                elif ownership == "no_owner_observed":
                    claim = diagnostic.get("claimed_address")
                    if isinstance(claim, str):
                        sockets = socket_snapshot(claim)
                        if sockets["listening_pids"] or address_accepts_connection(claim):
                            raise RuntimeError(f"{name} failed generation has a listener without an observed owner")
                else:
                    raise RuntimeError(f"{name} failed generation ownership is unresolved: {ownership!r}")
            supervisor_pid = state.get("supervisor_pid")
            ps_observation = None
            if isinstance(supervisor_pid, int):
                supervisor_identity = state.get("supervisor_start_identity")
                if not isinstance(supervisor_identity, dict) or not isinstance(supervisor_identity.get("start_seconds"), int):
                    raise RuntimeError(f"{name} supervisor PID has no recorded process identity")
                ps = subprocess.run(
                    ["ps", "-p", str(supervisor_pid), "-o", "pid=,ppid=,lstart="],
                    capture_output=True, text=True, timeout=15, check=False,
                )
                ps_observation = {"pid": supervisor_pid, "exit": ps.returncode,
                                  "current_pid_parent_start": ps.stdout.strip()[:240] or None}
                if ps.returncode not in (0, 1):
                    raise RuntimeError(f"{name} supervisor process inventory failed; ownership is held")
                if ps.stdout.strip():
                    fields = ps.stdout.strip().split(None, 2)
                    if len(fields) != 3 or fields[0] != str(supervisor_pid):
                        raise RuntimeError(f"{name} supervisor PID could not be reconciled")
                    current_start = int(datetime.strptime(fields[2], "%a %b %d %H:%M:%S %Y").timestamp())
                    if current_start == supervisor_identity["start_seconds"]:
                        raise RuntimeError(f"{name} recorded supervisor process remains; ownership is held")
                    ps_observation["same_recorded_process_present"] = False
                else:
                    ps_observation["same_recorded_process_present"] = False
        else:
            raise RuntimeError(f"{name} listener state is missing after a declared host-process launch")
        route = (process.get("listener") or {}).get("route") or {}
        checked.append({"name": name, "state": state.get("status"),
                        "pid_record_absent": True,
                        "route_domain": state.get("route_domain") or route.get("domain"),
                        "recorded_supervisor_observation": ps_observation})

    runtime = effigy_json(EFFIGY, checkout, env, "container", "hybrid", "status", "--json")
    if runtime.get("services"):
        raise RuntimeError("hybrid runtime still reports services after owned down")
    gateway = REFERENCE.private_gateway_status(checkout, gateway_root)
    routes = gateway.get("routes", [])
    route_domains = {route.get("domain") for route in routes}
    expected_domains = {row["route_domain"] for row in checked if row.get("route_domain")}
    if expected_domains & route_domains:
        raise RuntimeError("failed-generation route remains in the private gateway")
    return {"host_process_declarations": len(declarations), "checked_listeners": checked,
            "runtime_services": [], "owned_gateway_route_count": 0}


def verify_scope_down(checkout: Path, states: dict[str, dict], gateway_root: Path,
                      gateway_port: int, ca_file: Path,
                      survivor_instances: list[tuple[Path, dict[str, dict]]],
                      env: dict[str, str]) -> dict:
    down = effigy_json(EFFIGY, checkout, env, "container", "hybrid", "down", "--json", timeout=300)
    owned_routes = {state["route_domain"] for state in states.values()}
    for name, before in states.items():
        state_path = checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json"
        if not state_path.is_file():
            raise RuntimeError(f"{name} listener owner record is missing after down; cleanup is uncertain")
        after = json.loads(state_path.read_text(encoding="utf-8"))
        if after.get("status") != "stopped" or after.get("route_owner"):
            raise RuntimeError(f"{name} owner state did not record stopped/route-withdrawn after down")
        if address_accepts_connection(before["address"]):
            raise RuntimeError(f"listener {before['address']} still accepts connections after owned down")

    gateway_status = REFERENCE.private_gateway_status(checkout, gateway_root)
    route_map = {route["domain"]: route for route in gateway_status.get("routes", [])}
    if owned_routes & set(route_map):
        raise RuntimeError(f"main checkout routes remained after down: {sorted(owned_routes & set(route_map))}")

    survivor_count = 0
    ca_context = ssl.create_default_context(cafile=str(ca_file))
    survivor_receipts = []
    for sibling, sibling_states in survivor_instances:
        one = {"checkout": str(sibling), "listeners": []}
        for name, before in sibling_states.items():
            _, after = REFERENCE.managed_listener_state(sibling, name)
            if after["generation"] != before["generation"] or after["address"] != before["address"]:
                raise RuntimeError(f"foreign {name} listener changed while main checkout was retired")
            if not address_accepts_connection(after["address"]):
                raise RuntimeError(f"foreign {name} listener did not survive main checkout teardown")
            route = route_map.get(after["route_domain"])
            if not route or route.get("target") != after["address"]:
                raise RuntimeError(f"foreign {name} route did not survive main checkout teardown")
            request_path = "/v1/health" if name == "api" else "/"
            code, _, _ = REFERENCE.gateway_request(
                after["route_domain"], gateway_port, ca_context, request_path,
                {"Host": f"{after['route_domain']}:{gateway_port}"},
            )
            if code != 200:
                raise RuntimeError(f"foreign {name} route returned HTTP {code} after teardown")
            one["listeners"].append({"name": name, "address": after["address"],
                                     "generation": after["generation"], "route": after["route_domain"]})
            survivor_count += 1
        survivor_receipts.append(one)
    if survivor_count != 6:
        raise RuntimeError(f"expected six foreign Reference listeners/routes to survive; observed {survivor_count}")
    return {"down": down, "main_routes_withdrawn": sorted(owned_routes),
            "main_listener_sockets_closed": sorted(state["address"] for state in states.values()),
            "foreign_survivors": survivor_receipts}


def verify_stopped_scope(checkout: Path, states: dict[str, dict], gateway_root: Path) -> dict:
    closed = []
    processes = []
    for name, before in states.items():
        state_path = checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json"
        if not state_path.is_file():
            raise RuntimeError(f"{name} listener owner record is missing; cleanup is uncertain")
        after = json.loads(state_path.read_text(encoding="utf-8"))
        if after.get("status") != "stopped" or after.get("route_owner"):
            raise RuntimeError(f"{name} owner state did not record stopped/route-withdrawn")
        for role in ("supervisor", "child", "listener"):
            pid = before.get(f"{role}_pid")
            identity = before.get(f"{role}_start_identity")
            if pid is None:
                continue
            if not isinstance(pid, int) or not isinstance(identity, dict) or not isinstance(identity.get("start_seconds"), int):
                raise RuntimeError(f"{name} {role} process identity is incomplete; cleanup is uncertain")
            observation = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid=,lstart="],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if observation.returncode not in (0, 1):
                raise RuntimeError(f"read-only process identity check failed for {name} {role}")
            current_start = None
            if observation.stdout.strip():
                fields = observation.stdout.strip().split(None, 1)
                if len(fields) != 2 or fields[0] != str(pid):
                    raise RuntimeError(f"{name} {role} PID could not be reconciled; cleanup is uncertain")
                try:
                    current_start = int(datetime.strptime(fields[1], "%a %b %d %H:%M:%S %Y").timestamp())
                except ValueError as error:
                    raise RuntimeError(f"{name} {role} PID start time is unreadable; cleanup is uncertain") from error
            same_process = current_start == identity["start_seconds"]
            processes.append({"name": name, "role": role, "pid": pid,
                              "recorded_start_seconds": identity["start_seconds"],
                              "current_start_seconds": current_start,
                              "same_recorded_process_present": same_process})
            if same_process:
                raise RuntimeError(f"recorded {name} {role} process identity is still present after down")
        sockets = socket_snapshot(before["address"])
        if sockets["listening_pids"]:
            raise RuntimeError(f"listener socket {before['address']} is still owned after down")
        if address_accepts_connection(before["address"]):
            raise RuntimeError(f"listener {before['address']} still accepts connections after down")
        closed.append({"address": before["address"], "listening_pids": sockets["listening_pids"]})
    routes = REFERENCE.private_gateway_status(checkout, gateway_root).get("routes", [])
    route_domains = {route.get("domain") for route in routes}
    owned_domains = {state["route_domain"] for state in states.values()}
    if route_domains & owned_domains:
        raise RuntimeError(f"owned routes remain after down: {sorted(route_domains & owned_domains)}")
    return {"process_identities_absent": processes, "closed_listeners": closed,
            "withdrawn_routes": sorted(owned_domains)}


def verify_no_host_children_started(checkout: Path, env: dict[str, str]) -> dict:
    """Bound early-startup cleanup only when no managed child was ever declared."""
    manifest = (checkout / "effigy.toml").read_text(encoding="utf-8")
    if "[[containers.hybrid.host_processes]]" in manifest:
        raise RuntimeError("managed host processes were declared; their owner state must be verified")
    state_dir = checkout / ".effigy/runtime/host-processes/hybrid"
    state_files = [path for path in state_dir.rglob("*") if path.is_file()] if state_dir.exists() else []
    if state_files:
        raise RuntimeError("host-process state files exist without captured owner state")
    inventory = run([EFFIGY, "container", "status", "--global", "--json"],
                    env=env, timeout=120, print_output=False)
    envelope = json.loads(inventory.stdout)
    if envelope.get("ok") is not True:
        raise RuntimeError("Effigy global container inventory failed during early cleanup")
    count = (envelope.get("result") or {}).get("environment_count")
    if count != 0:
        raise RuntimeError(f"early cleanup found {count!r} runtime environments; profile purge is held")
    return {"host_process_declarations": 0, "host_process_state_files": 0,
            "global_runtime_environment_count": 0}


def verify_interrupted_probe_reconciled(state: dict, claimed_address: str | None) -> dict:
    """Reconcile a failed readiness generation using state and live resource checks."""
    if state.get("schema") != "effigy.managed.host-listener-state.v1":
        raise RuntimeError("interrupted child retained an unsupported owner-state schema")
    if state.get("route_owner") is not None:
        raise RuntimeError("interrupted child still owns a published route after exact-scope down")

    status = state.get("status")
    diagnostic = state.get("diagnostic") or {}
    if status == "failed":
        expected_fields = {
            "report", "claimed_address", "ownership", "candidates_inspected",
            "observed_listener_pid", "http_probe", "http_status", "route",
        }
        if set(diagnostic) != expected_fields:
            raise RuntimeError("failed interruption state did not retain the bounded eight-field diagnostic")
        if not (
            diagnostic.get("report") == "accepted"
            and diagnostic.get("ownership") == "exclusive_owner_observed"
            and diagnostic.get("http_probe") == "status_mismatch"
            and diagnostic.get("http_status") == 503
            and diagnostic.get("route") == "not_reached"
        ):
            raise RuntimeError("failed interruption state does not prove an owned 503 before publication")
        if diagnostic.get("claimed_address") != claimed_address:
            raise RuntimeError("failed interruption state changed the generation's claimed address")
        for field in (
            "address", "internal_url", "public_url", "route_owner", "child_pid",
            "child_boot_identity", "child_start_identity", "listener_pid",
            "listener_boot_identity", "listener_start_identity",
        ):
            if state.get(field) is not None:
                raise RuntimeError(f"failed interruption retained active owner field {field}")
        terminal = "failed_with_owner_cleared"
    elif status == "stopped":
        terminal = "stopped"
    else:
        raise RuntimeError(f"interrupted child remained in nonterminal owner state {status!r}")

    if isinstance(claimed_address, str):
        sockets = socket_snapshot(claimed_address)
        if sockets["listening_pids"] or address_accepts_connection(claimed_address):
            raise RuntimeError("interrupted child still owns or serves its claimed listener after exact-scope down")
    else:
        sockets = {"address": None, "listening_pids": []}

    supervisor_pid = state.get("supervisor_pid")
    supervisor_identity = state.get("supervisor_start_identity")
    supervisor_observation = None
    if isinstance(supervisor_pid, int):
        if not isinstance(supervisor_identity, dict) or not isinstance(supervisor_identity.get("start_seconds"), int):
            raise RuntimeError("interrupted state retained a supervisor PID without a verifiable process identity")
        ps = subprocess.run(
            ["ps", "-p", str(supervisor_pid), "-o", "pid=,lstart="],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if ps.returncode not in (0, 1):
            raise RuntimeError("read-only supervisor process identity check failed after interruption")
        current_start = None
        if ps.stdout.strip():
            fields = ps.stdout.strip().split(None, 1)
            if len(fields) != 2 or fields[0] != str(supervisor_pid):
                raise RuntimeError("interrupted supervisor PID could not be reconciled")
            current_start = int(datetime.strptime(fields[1], "%a %b %d %H:%M:%S %Y").timestamp())
        if current_start == supervisor_identity["start_seconds"]:
            raise RuntimeError("the recorded interrupted supervisor process is still present after down")
        supervisor_observation = {
            "pid": supervisor_pid,
            "recorded_start_seconds": supervisor_identity["start_seconds"],
            "current_start_seconds": current_start,
            "same_recorded_process_present": False,
        }
    return {
        "terminal_status": terminal,
        "diagnostic": diagnostic,
        "active_owner_fields_cleared": status == "failed",
        "listener_socket": sockets,
        "recorded_supervisor_observation": supervisor_observation,
        "exact_scope_down_completed": True,
    }


def baseline_consumer_files(checkout: Path) -> dict[str, bytes | None]:
    relative_files = (
        "effigy.toml",
        "config/effigy.toml",
        "apps/acme-api/crates/api/src/main.rs",
        "apps/acme-front/svelte.config.js",
        "apps/acme-front/src/lib/config/public-api.generated.ts",
        "apps/acme-admin/svelte.config.js",
        "apps/acme-admin/src/lib/config/public-api.generated.ts",
    )
    return {
        relative: (checkout / relative).read_bytes() if (checkout / relative).is_file() else None
        for relative in relative_files
    }


def fixed_default_ports_available() -> list[int]:
    occupied = []
    for port in (41001, 41002, 41003, 5432, 1025, 8025, 9000, 9001):
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            occupied.append(port)
        elif result.returncode not in (0, 1):
            raise RuntimeError(f"read-only listener inventory failed for default port {port}")
    return occupied


def replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"could not update fixture-only {label}")
    return updated


def configure_app_urls(checkout: Path, domains: dict[str, str], postgres_port: int,
                       gateway_port: int) -> None:
    config_path = checkout / "config/effigy.toml"
    config = config_path.read_text(encoding="utf-8")
    config = replace_once(config, r'^public_host\s*=\s*"[^"]+"$',
                          f'public_host = "{domains["api"]}"', "API public host")
    config = replace_once(config, r'^url\s*=\s*"postgres://[^"]+"$',
                          f'url = "postgres://postgres:qualification-local-only@127.0.0.1:{postgres_port}/acme"',
                          "host-reachable Postgres URL")
    origins = [f"https://{domains[name]}:{gateway_port}" for name in ("front", "admin")]
    config = replace_once(config, r'^allowed_origins\s*=\s*\[[^\]]*\]$',
                          "allowed_origins = [" + ", ".join(json.dumps(x) for x in origins) + "]",
                          "browser origin allowlist")
    config = replace_once(config, r'^cookie_domain\s*=\s*"[^"]+"$',
                          f'cookie_domain = ".{domains["front"].removeprefix("acme.")}"',
                          "fixture cookie domain")
    config = replace_once(config, r'^app_url\s*=\s*"[^"]+"$',
                          f'app_url = "https://{domains["admin"]}:{gateway_port}"',
                          "admin browser URL")
    config = replace_once(config, r'^webauthn_rp_id\s*=\s*"[^"]+"$',
                          f'webauthn_rp_id = "{domains["admin"]}"', "fixture WebAuthn RP ID")
    config = replace_once(config, r'^webauthn_rp_origin\s*=\s*"[^"]+"$',
                          f'webauthn_rp_origin = "https://{domains["admin"]}:{gateway_port}"',
                          "fixture WebAuthn RP origin")
    config_path.write_text(config, encoding="utf-8")

    # Reference's current dev branch hardcodes the S3 gateway URL and ignores
    # ACME_S3_ENDPOINT. Patch only the disposable source clone so the real app
    # uses the assigned loopback MinIO endpoint while public URLs stay on HTTPS.
    api_source_path = checkout / "apps/acme-api/crates/api/src/main.rs"
    api_source = api_source_path.read_text(encoding="utf-8")
    old_dev_endpoint = 'let s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");'
    new_dev_endpoint = '''let mut s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");
        if let Ok(endpoint) = std::env::var("ACME_S3_ENDPOINT") {
            s3_config = s3_config.endpoint_url(endpoint);
        }
        if let Ok(public_url_base) = std::env::var("ACME_S3_PUBLIC_URL_BASE") {
            s3_config = s3_config.public_url_base(public_url_base);
        }'''
    old_count = api_source.count(old_dev_endpoint)
    new_count = api_source.count(new_dev_endpoint)
    if old_count == 1 and new_count == 0:
        api_source_path.write_text(api_source.replace(old_dev_endpoint, new_dev_endpoint, 1), encoding="utf-8")
    elif old_count == 0 and new_count == 1:
        # Recovery paths reconfigure the same disposable checkout after a
        # service restart. Accept the exact already-applied adapter once, but
        # reject ambiguous or partially edited source rather than stacking a
        # second patch or silently adapting a different upstream version.
        pass
    else:
        raise RuntimeError("could not apply or verify the exact disposable Reference dev S3 endpoint override")


def append_hybrid_services(checkout: Path, declared_domains: dict[str, str], project: str) -> None:
    manifest = checkout / "effigy.toml"
    text = manifest.read_text(encoding="utf-8")
    if "[containers.hybrid]" in text:
        raise RuntimeError("private Reference fixture already has a hybrid container declaration")
    quote = json.dumps
    parts = [
        "\n# Qualification-only hybrid services; generated inside a disposable Reference checkout.\n",
        "[containers.hybrid]\n",
        'driver = "colima"\nprofile = "effigy"\nstartup = "detached"\n',
        # The hybrid profile is service-only; `/` exists in its Postgres
        # primary container and is the correct CWD for Effigy's exec-ready probe.
        f"project_name = {quote(project)}\nworking_dir = \"/\"\nprimary_service = \"postgres\"\n\n",
        "[containers.hybrid.services.postgres]\ncatalog = \"postgres\"\ndatabase = \"acme\"\npassword = \"qualification-local-only\"\n\n",
        "[containers.hybrid.services.mailpit]\ncatalog = \"mailpit\"\n\n",
        "[containers.hybrid.services.minio]\ncatalog = \"minio\"\n\n",
        "[containers.hybrid.dns]\nroutes = [\n",
        f"  {{ domain = {quote(declared_domains['s3'])}, tls = true, port = 9000, service = \"minio\" }},\n",
        f"  {{ domain = {quote(declared_domains['minio'])}, tls = true, port = 9001, service = \"minio\" }},\n",
        "]\n\n",
    ]
    checkout_manifest = checkout / "effigy.toml"
    checkout_manifest.write_text(text + "".join(parts), encoding="utf-8")


def append_reference_host_processes(checkout: Path, names: dict[str, str], gateway_port: int,
                                    minio_port: int, bundle_root: Path) -> None:
    manifest = checkout / "effigy.toml"
    text = manifest.read_text(encoding="utf-8")
    if "[[containers.hybrid.host_processes]]" in text:
        raise RuntimeError("private Reference fixture already has host-process declarations")
    quote = json.dumps
    rust_command = (
        f"python3 {quote(str(bundle_root / 'scripts/dev/managed-rust-listener.py'))} -- "
        "cargo run --manifest-path apps/acme-api/Cargo.toml -p acme-api"
    )
    # Reference's actual development adapter is Bun + Vite. Running the
    # Node-compatible helper under Bun preserves that runtime contract.
    vite_command = f"bun {quote(str(bundle_root / 'scripts/dev/managed-vite-listener.mjs'))}"
    public = {name: f"https://{names[name]}:{gateway_port}" for name in ("front", "admin", "api")}
    minio_internal = f"http://127.0.0.1:{minio_port}"
    minio_public = f"https://{names['s3']}:{gateway_port}"
    parts = [
        "\n# Fixture-only host processes, appended after real service port discovery.\n",
        "[[containers.hybrid.host_processes]]\n",
        'name = "api"\n',
        f"run = {quote(rust_command)}\ncwd = \".\"\nrestart = \"on-failure\"\n",
        "env = { ",
        f"ENVIRONMENT = \"effigy\", ACME_S3_ENDPOINT = {quote(minio_internal)}, ",
        f"ACME_S3_PUBLIC_URL_BASE = {quote(minio_public)}",
        " }\n",
        "[containers.hybrid.host_processes.listener]\nbind = \"127.0.0.1:0\"\n",
        "[containers.hybrid.host_processes.listener.readiness]\npath = \"/v1/health\"\nstatus = 200\ntimeout_secs = 540\n",
        "[containers.hybrid.host_processes.listener.route]\n",
        f"domain = {quote(names['api'])}\ntls = true\n\n",
    ]
    for app_name in ("front", "admin"):
        app_dir = "acme-front" if app_name == "front" else "acme-admin"
        public_config = {
            "EFFIGY_PROFILE_PUBLIC_URL": public[app_name],
            "EFFIGY_PROFILE_FRONT_PUBLIC_URL": public["front"],
            "EFFIGY_PROFILE_ADMIN_PUBLIC_URL": public["admin"],
            "EFFIGY_PROFILE_GATEWAY_HTTPS_PORT": str(gateway_port),
            "EFFIGY_PROFILE_PUBLIC_CONFIG_FILE": "src/lib/config/public-api.generated.ts",
            "EFFIGY_PROFILE_PUBLIC_CONFIG_GENERATOR": "scripts/generate-public-config.ts",
            "EFFIGY_PROFILE_VITE_CONFIG": "vite.config.ts",
            "ENVIRONMENT": "effigy",
        }
        env_table = ", ".join(f"{key} = {quote(value)}" for key, value in public_config.items())
        parts.extend([
            "[[containers.hybrid.host_processes]]\n",
            f"name = {quote(app_name)}\n",
            f"run = {quote(vite_command)}\n",
            f"cwd = {quote('apps/' + app_dir)}\nrestart = \"on-failure\"\n",
            'depends_on = ["api"]\n',
            f"env = {{ {env_table} }}\n",
            "[containers.hybrid.host_processes.listener]\nbind = \"127.0.0.1:0\"\n",
            "[containers.hybrid.host_processes.listener.readiness]\npath = \"/__effigy/ready\"\nstatus = 200\ntimeout_secs = 540\n",
            "[containers.hybrid.host_processes.listener.route]\n",
            f"domain = {quote(names[app_name])}\ntls = true\n\n",
        ])
    task_name = "qualification:hybrid-up"
    if f'[tasks."{task_name}"]' in text:
        raise RuntimeError("private Reference fixture already contains the secret-bearing hybrid task")
    task_command = shlex.join([
        EFFIGY, "--repo", str(checkout), "container", "hybrid", "up", "--detach", "--json",
    ])
    parts.extend([
        f'\n[tasks."{task_name}"]\n',
        f"run = {quote(task_command)}\n",
        'run_in = "host"\n',
        'secrets = "required"\n',
    ])
    manifest.write_text(text + "".join(parts), encoding="utf-8")


def hybrid_up_with_declared_task_secrets(checkout: Path, env: dict[str, str]) -> dict:
    """Start through a managed task so declared task secrets reach host children."""
    result = run(
        [EFFIGY, "--repo", str(checkout), "qualification:hybrid-up"],
        cwd=checkout, env=env, timeout=900, print_output=False,
    )
    output = result.stdout.encode()
    return {
        "task": "qualification:hybrid-up",
        "exit": result.returncode,
        "stdout_bytes": len(output),
        "stdout_sha256": hashlib.sha256(output).hexdigest(),
    }


def recover_reference_apps(checkout: Path, original_manifest: str, env: dict[str, str],
                           gateway_port: int, label: str) -> tuple[dict, dict[str, dict]]:
    """Restart services first, then actual Reference apps via their secret-bearing task."""
    manifest_path = checkout / "effigy.toml"
    host_marker = "[[containers.hybrid.host_processes]]"
    if host_marker not in original_manifest:
        raise RuntimeError("original Reference fixture manifest omitted its managed app declarations")
    manifest_path.write_text(original_manifest.split(host_marker, 1)[0], encoding="utf-8")
    service_up = effigy_json(EFFIGY, checkout, env, "container", "hybrid", "up",
                             "--detach", "--json", timeout=600)
    service_status = effigy_json(EFFIGY, checkout, env, "container", "hybrid", "status", "--json")
    services = {item["name"]: item["status"] for item in service_status.get("services", [])}
    if any(services.get(name) != "Up" for name in ("postgres", "mailpit", "minio")):
        raise RuntimeError("Reference services did not recover after the owned host-process probe")
    pg_port = REFERENCE.service_host_port(service_status, 5432)
    if pg_port is None:
        raise RuntimeError("Reference Postgres did not report its recovered loopback port")
    names = route_domains(effigy_json(EFFIGY, checkout, env, "container", "hosts", "--json"))
    configure_app_urls(checkout, names, pg_port, gateway_port)
    manifest_path.write_text(original_manifest, encoding="utf-8")
    resumed = hybrid_up_with_declared_task_secrets(checkout, env)
    if resumed.get("exit") != 0:
        raise RuntimeError("Reference host-process recovery task failed after exact-scope reconciliation")
    recovered_states = {
        name: REFERENCE.managed_listener_state(checkout, name)[1]
        for name in ("api", "front", "admin")
    }
    observe_routes(checkout, Path(env["EFFIGY_GATEWAY_PRIVATE_STATE_ROOT"]), env,
                   recovered_states, gateway_port)
    capture = capture_runtime_evidence(
        checkout, ["api", "front", "admin"],
        Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]), label,
    )
    return ({"service_up": service_up, "service_status": services,
             "postgres_port": pg_port, "host_process_recovery": resumed,
             "runtime_capture": capture}, recovered_states)


def append_occupied_port_child(checkout: Path, foreign_address: str, collision_domain: str,
                               bundle_root: Path) -> None:
    """Add one strict-bind child that must fail against a live sibling listener."""
    manifest = checkout / "effigy.toml"
    text = manifest.read_text(encoding="utf-8")
    if 'name = "collision-probe"' in text:
        raise RuntimeError("private Reference fixture already contains a collision probe")
    quote = json.dumps
    command = f"python3 {quote(str(bundle_root / 'scripts/qualification/managed-listener-probe.py'))}"
    host, separator, port = foreign_address.rpartition(":")
    if not separator or host != "127.0.0.1" or not port.isdigit():
        raise RuntimeError("collision proof requires the actual IPv4 loopback address of a live foreign listener")
    text += (
        "\n# Qualification-only child intentionally collides with a live sibling API socket.\n"
        "[[containers.hybrid.host_processes]]\n"
        'name = "collision-probe"\n'
        f"run = {quote(command)}\ncwd = \".\"\nrestart = \"never\"\n"
        'env = { EFFIGY_PROFILE_WAIT_ON_EADDRINUSE = "1" }\n'
        "[containers.hybrid.host_processes.listener]\n"
        f"bind = {quote(foreign_address)}\n"
        "[containers.hybrid.host_processes.listener.readiness]\n"
        "path = \"/\"\nstatus = 200\ntimeout_secs = 10\n"
        "[containers.hybrid.host_processes.listener.route]\n"
        f"domain = {quote(collision_domain)}\ntls = true\n"
    )
    manifest.write_text(text, encoding="utf-8")


def append_interrupted_readiness_child(checkout: Path, route_domain: str,
                                       bundle_root: Path) -> None:
    manifest = checkout / "effigy.toml"
    text = manifest.read_text(encoding="utf-8")
    if 'name = "interrupted-probe"' in text:
        raise RuntimeError("private Reference fixture already contains an interruption probe")
    quote = json.dumps
    command = f"python3 {quote(str(bundle_root / 'scripts/qualification/managed-listener-probe.py'))}"
    text += (
        "\n# Qualification-only live child used to interrupt an unready host startup.\n"
        "[[containers.hybrid.host_processes]]\n"
        'name = "interrupted-probe"\n'
        f"run = {quote(command)}\ncwd = \".\"\nrestart = \"never\"\n"
        'env = { EFFIGY_PROFILE_PROBE_HTTP_STATUS = "503" }\n'
        "[containers.hybrid.host_processes.listener]\nbind = \"127.0.0.1:0\"\n"
        "[containers.hybrid.host_processes.listener.readiness]\n"
        "path = \"/\"\nstatus = 200\ntimeout_secs = 90\n"
        "[containers.hybrid.host_processes.listener.route]\n"
        f"domain = {quote(route_domain)}\ntls = true\n"
    )
    manifest.write_text(text, encoding="utf-8")


def assert_foreign_instances_live(instances: list[tuple[Path, dict[str, dict]]],
                                  gateway_root: Path, gateway_port: int) -> list[dict]:
    ca_context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
    receipts = []
    for checkout, states in instances:
        one = {"checkout": str(checkout), "listeners": []}
        routes = {route.get("domain"): route for route in
                  REFERENCE.private_gateway_status(checkout, gateway_root).get("routes", [])}
        for name, before in states.items():
            _, after = REFERENCE.managed_listener_state(checkout, name)
            if after["generation"] != before["generation"] or after["address"] != before["address"]:
                raise RuntimeError(f"foreign Reference listener {name} changed across the main-scope interruption")
            if not address_accepts_connection(after["address"]):
                raise RuntimeError(f"foreign Reference listener {name} stopped across the main-scope interruption")
            route = routes.get(after["route_domain"])
            if not route or route.get("target") != after["address"]:
                raise RuntimeError(f"foreign Reference route {name} changed across the main-scope interruption")
            path = "/v1/health" if name == "api" else "/"
            code, _, _ = REFERENCE.gateway_request(
                after["route_domain"], gateway_port, ca_context, path,
                {"Host": f"{after['route_domain']}:{gateway_port}"},
            )
            if code != 200:
                raise RuntimeError(f"foreign Reference route {name} returned HTTP {code} after interruption")
            one["listeners"].append({"name": name, "address": after["address"],
                                     "generation": after["generation"], "route": after["route_domain"],
                                     "https_status": code})
        receipts.append(one)
    return receipts


def prove_interrupted_startup(main_checkout: Path, main_states: dict[str, dict],
                              foreign_instances: list[tuple[Path, dict[str, dict]]],
                              gateway_root: Path, gateway_port: int,
                              env: dict[str, str]) -> tuple[dict, dict[str, dict]]:
    manifest_path = main_checkout / "effigy.toml"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    interrupted_domain = f"interrupted.{main_states['api']['route_domain']}"
    scope_down_before = effigy_json(EFFIGY, main_checkout, env, "container", "hybrid", "down", "--json", timeout=300)
    stopped_before = verify_stopped_scope(main_checkout, main_states, gateway_root)
    append_interrupted_readiness_child(main_checkout, interrupted_domain, REPO)
    # The fixture's API requires the consumer's declared vault secrets. Launch
    # through its task contract, which supplies those values to the owned
    # child process; direct `container hybrid up` would test an incomplete env.
    args = [EFFIGY, "--repo", str(main_checkout), "qualification:hybrid-up"]
    print(f"COMMAND: {' '.join(args)}", flush=True)
    process = subprocess.Popen(args, cwd=main_checkout, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               start_new_session=True)
    state_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy/interrupted-probe.listener.json"
    observed_state = None
    observed_ready_failure = False
    deadline = time.monotonic() + 180
    while process.poll() is None and time.monotonic() < deadline:
        if state_path.is_file():
            try:
                candidate = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                candidate = None
            diagnostic = candidate.get("diagnostic") if isinstance(candidate, dict) else None
            if isinstance(diagnostic, dict) and diagnostic.get("http_status") == 503:
                observed_state = candidate
                observed_ready_failure = True
                break
        time.sleep(0.1)

    interruption_signal_sent = False
    process_group_id = None
    if process.poll() is None:
        process_group_id = os.getpgid(process.pid)
        if process_group_id != process.pid:
            raise RuntimeError("secret-bearing startup task did not retain its owned process group")
        os.killpg(process_group_id, signal.SIGINT)
        interruption_signal_sent = True
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=10)
    print(f"EXIT: {process.returncode}", flush=True)
    print(f"INTERRUPTED COMMAND OUTPUT: captured stdout={len(stdout)} bytes stderr={len(stderr)} bytes", flush=True)
    command_error = safe_effigy_error(stdout) or safe_effigy_error(stderr)
    if not interruption_signal_sent:
        print(
            "UNPROVEN interrupting the pending Effigy startup: the command exited before SIGINT "
            f"(exit={process.returncode}, bounded_error={command_error!r})",
            flush=True,
        )

    interrupt_before = observed_state
    diagnostic = (interrupt_before or {}).get("diagnostic") or {}
    process_identity = {}
    if interrupt_before:
        for key in ("supervisor_pid", "child_pid", "supervisor_start_identity", "child_start_identity",
                    "runtime_generation", "generation", "address"):
            if key in interrupt_before:
                process_identity[key] = interrupt_before[key]
    address = (interrupt_before or {}).get("address") or diagnostic.get("claimed_address")
    if isinstance(address, dict):
        address = f"{address.get('ip')}:{address.get('port')}"
    pre_interrupt_capture = capture_runtime_evidence(
        main_checkout,
        ["api", "front", "admin", "interrupted-probe"],
        Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]),
        "before-interrupted-startup-reconcile",
    )
    pending_states = {}
    runtime_dir = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy"
    for name in ("api", "front", "admin", "interrupted-probe"):
        owner_path = runtime_dir / f"{name}.listener.json"
        if owner_path.is_file():
            candidate = json.loads(owner_path.read_text(encoding="utf-8"))
            if candidate.get("status") == "ready" and candidate.get("route_owner"):
                pending_states[name] = candidate

    # Reconcile only this private checkout with Effigy's recorded owner state.
    stopped = effigy_json(EFFIGY, main_checkout, env, "container", "hybrid", "down", "--json", timeout=300)
    stopped_pending = (
        verify_stopped_scope(main_checkout, pending_states, gateway_root)
        if pending_states else {"ready_listener_count": 0}
    )
    full_scope_reconciliation = verify_failed_scope_reconciled(main_checkout, gateway_root, env)
    interrupt_after = None
    if state_path.is_file():
        interrupt_after = json.loads(state_path.read_text(encoding="utf-8"))
    elif interruption_signal_sent:
        raise RuntimeError("interrupted child state was not retained after exact-scope reconciliation")
    if interrupt_after is None:
        raise RuntimeError("interrupted child has no retained state after exact-scope reconciliation")
    interrupted_diagnostic = interrupt_after.get("diagnostic") or {}
    interrupted_claim = interrupted_diagnostic.get("claimed_address")
    interrupted_reconciliation = verify_interrupted_probe_reconciled(
        interrupt_after,
        interrupted_claim if isinstance(interrupted_claim, str) else None,
    )
    for name in ("api", "front", "admin", "interrupted-probe"):
        owner_path = runtime_dir / f"{name}.listener.json"
        if not owner_path.is_file():
            continue
        after = json.loads(owner_path.read_text(encoding="utf-8"))
        if name != "interrupted-probe" and (after.get("status") != "stopped" or after.get("route_owner")):
            raise RuntimeError(f"owned {name} remained uncertain after interrupted-scope reconciliation")
        if name == "interrupted-probe":
            continue
        before = main_states.get(name) or pending_states.get(name) or {}
        address = before.get("address") or (before.get("diagnostic") or {}).get("claimed_address")
        if isinstance(address, dict):
            address = f"{address.get('ip')}:{address.get('port')}"
        if isinstance(address, str) and address_accepts_connection(address):
            raise RuntimeError(f"owned {name} listener remained open after interrupted-scope reconciliation")
    if isinstance(address, str) and address_accepts_connection(address):
        raise RuntimeError("interrupted child socket remained open after owner reconciliation")
    gateway_routes = {route.get("domain") for route in
                      REFERENCE.private_gateway_status(main_checkout, gateway_root).get("routes", [])}
    if interrupted_domain in gateway_routes:
        raise RuntimeError("interrupted, unready child published a gateway route")
    foreign_receipts = assert_foreign_instances_live(foreign_instances, gateway_root, gateway_port)

    recovery, recovered_states = recover_reference_apps(
        main_checkout, original_manifest, env, gateway_port,
        "after-interrupted-startup-recovery",
    )

    control_passed = bool(
        interruption_signal_sent
        and observed_ready_failure
        and interrupt_after
        and interrupted_reconciliation.get("terminal_status") in {"stopped", "failed_with_owner_cleared"}
        and not interrupt_after.get("route_owner")
        and interrupted_domain not in gateway_routes
    )
    receipt = {
        "status": "passed" if control_passed else "unproven",
        "interrupted_effigy_command_exit": process.returncode,
        "signal_sent_to_owned_effigy_process_group": "SIGINT" if interruption_signal_sent else None,
        "owned_process_group_id": process_group_id,
        "launcher_pid": process.pid,
        "command_error": command_error,
        "ready_check_observed_503_before_interrupt": observed_ready_failure,
        "interrupted_diagnostic": diagnostic,
        "interrupted_process_identity": process_identity,
        "pre_interrupt_runtime_capture": pre_interrupt_capture,
        "scope_down_before_interruption": scope_down_before,
        "stopped_applications_before_interruption": stopped_before,
        "ready_processes_from_interrupted_generation": pending_states,
        "stopped_processes_after_interruption": stopped_pending,
        "all_declared_processes_reconciled": full_scope_reconciliation,
        "interrupted_owner_reconciliation": interrupted_reconciliation,
        "interrupted_state_after_reconcile": {
            "status": interrupt_after.get("status") if interrupt_after else "not_created",
            "route_owner": interrupt_after.get("route_owner") if interrupt_after else None,
        },
        "interrupted_route_absent": interrupted_domain not in gateway_routes,
        "foreign_instances_after_interrupt": foreign_receipts,
        "exact_scope_down": stopped,
        "recovery": recovery,
        "recovered_listener_generations": {name: state["generation"] for name, state in recovered_states.items()},
    }
    if not control_passed:
        receipt["qualification_limit"] = (
            "the exact pending-start interruption and retained unready-owner state were not both observed"
        )
        print(
            "UNPROVEN exact startup interruption; exact-scope reconciliation/recovery completed and both "
            "other Reference scopes remained CA-verified and live",
            flush=True,
        )
    else:
        print("PASS interrupting the owned Effigy startup command was followed by exact-scope down and re-up; "
              "both other Reference scopes remained CA-verified and live", flush=True)
    return receipt, recovered_states


def prove_failed_collision_is_scoped(main_checkout: Path, main_states: dict[str, dict],
                                     foreign_checkout: Path, foreign_states: dict[str, dict],
                                     gateway_root: Path, gateway_port: int,
                                     env: dict[str, str]) -> tuple[dict, dict[str, dict]]:
    foreign_api = foreign_states["api"]
    collision_domain = f"collision.{main_states['api']['route_domain']}"
    manifest_path = main_checkout / "effigy.toml"
    original_manifest = manifest_path.read_text(encoding="utf-8")
    host_marker = "[[containers.hybrid.host_processes]]"
    if host_marker not in original_manifest:
        raise RuntimeError("Reference fixture omitted its app host-process declarations")
    down_before = effigy_json(EFFIGY, main_checkout, env, "container", "hybrid", "down", "--json", timeout=300)
    stopped_before = verify_stopped_scope(main_checkout, main_states, gateway_root)

    # Exercise the strict-bind failure in a clean managed scope. The actual
    # Reference apps were already qualified concurrently; keeping them declared
    # here would make `up` re-enter their existing supervisors and would test a
    # second-start condition instead of the occupied socket.
    manifest_path.write_text(original_manifest.split(host_marker, 1)[0], encoding="utf-8")
    append_occupied_port_child(main_checkout, foreign_api["address"], collision_domain, REPO)
    args = [EFFIGY, "--repo", str(main_checkout), "container", "hybrid", "up", "--detach", "--json"]
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(args, cwd=main_checkout, env=env, capture_output=True,
                            text=True, timeout=300, check=False)
    print(f"EXIT: {result.returncode}", flush=True)
    command_receipt = {
        "exit": result.returncode,
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
        "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
        "redacted_error": safe_effigy_error(result.stdout) or safe_effigy_error(result.stderr),
    }
    if result.returncode == 0:
        raise RuntimeError("Effigy accepted a managed child that could not bind the foreign occupied port")
    state_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy/collision-probe.listener.json"
    if not state_path.is_file():
        gateway_status = REFERENCE.private_gateway_status(main_checkout, gateway_root)
        routes = {route.get("domain"): route for route in gateway_status.get("routes", [])}
        if collision_domain in routes:
            raise RuntimeError("failed collision launch published a route without a retained owner state")
        foreign_route = routes.get(foreign_api["route_domain"])
        if not foreign_route or foreign_route.get("target") != foreign_api["address"]:
            raise RuntimeError("failed collision launch removed or retargeted the unaffected foreign API route")
        if not address_accepts_connection(foreign_api["address"]):
            raise RuntimeError("failed collision launch stopped the foreign listener occupying the requested port")
        ca_context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
        code, _, _ = REFERENCE.gateway_request(
            foreign_api["route_domain"], gateway_port, ca_context, "/v1/health",
            {"Host": f"{foreign_api['route_domain']}:{gateway_port}"},
        )
        if code != 200:
            raise RuntimeError(f"foreign API HTTPS route returned {code} after collision startup failure")
        for name, before in main_states.items():
            owner_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json"
            if not owner_path.is_file():
                raise RuntimeError(f"collision fixture lost the stopped {name} owner record")
            after = json.loads(owner_path.read_text(encoding="utf-8"))
            if after.get("status") != "stopped" or after.get("route_owner"):
                raise RuntimeError(f"collision fixture changed the stopped {name} owner")
            if address_accepts_connection(before["address"]):
                raise RuntimeError(f"collision fixture reopened the stopped {name} listener")
        down_unknown = effigy_json(EFFIGY, main_checkout, env, "container", "hybrid", "down", "--json", timeout=300)
        manifest_path.write_text(original_manifest, encoding="utf-8")
        receipt = {
            "status": "unproven",
            "command": command_receipt,
            "collision_owner_state": "missing",
            "collision_route_absent": True,
            "foreign_listener_survived": True,
            "foreign_route": foreign_api["route_domain"],
            "foreign_address": foreign_api["address"],
            "foreign_https_status": code,
            "scope_down_before_collision": down_before,
            "stopped_applications_before_collision": stopped_before,
            "down_after_missing_owner_state": down_unknown,
            "failed_scope_runtime_capture": capture_runtime_evidence(
                main_checkout, ["collision-probe"],
                Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]),
                "after-occupied-port-failure-without-owner-state",
            ),
            "qualification_limit": (
                "the clean-scope start returned nonzero without retaining a failed-generation owner record; "
                "the exact error is reported and cleanup stops without reusing or purging this scope"
            ),
        }
        return receipt, main_states
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError:
        envelope = None
    if isinstance(envelope, dict) and envelope.get("ok") is True:
        raise RuntimeError("Effigy task reported success while the occupied-port launch returned nonzero")
    failed = json.loads(state_path.read_text(encoding="utf-8"))
    diagnostic = failed.get("diagnostic")
    required_diagnostic = {
        "report", "claimed_address", "ownership", "candidates_inspected",
        "observed_listener_pid", "http_probe", "http_status", "route",
    }
    if failed.get("status") != "failed" or not isinstance(diagnostic, dict):
        raise RuntimeError("occupied-port failure did not retain a failed state and generation diagnostic")
    if set(diagnostic) != required_diagnostic:
        raise RuntimeError("occupied-port diagnostic fields differ from the supported eight-field contract")
    if diagnostic.get("route") != "not_reached" or failed.get("route_owner"):
        raise RuntimeError("Effigy advanced to or published a route before it owned the strict-bound listener")
    spec_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy/collision-probe.spec.json"
    if not spec_path.is_file():
        raise RuntimeError("occupied-port start did not retain the declared managed-child runtime spec")
    collision_spec = json.loads(spec_path.read_text(encoding="utf-8"))
    listener_spec = collision_spec.get("listener") or {}
    if listener_spec.get("bind") != foreign_api["address"]:
        raise RuntimeError("managed collision child did not receive the exact foreign listener bind address")
    child_log_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy/collision-probe.log"
    child_errors = safe_child_error_excerpt(child_log_path.read_text(encoding="utf-8", errors="replace")) if child_log_path.is_file() else []
    if not any(
        "address already in use" in line.lower()
        or re.search(r"errno\s*=\s*(48|98|10048)\b", line, re.IGNORECASE)
        for line in child_errors
    ):
        raise RuntimeError("occupied-port child exit did not retain an EADDRINUSE diagnostic")
    if not (
        diagnostic.get("report") in {"absent", "not_observed"}
        and diagnostic.get("ownership") == "not_reached"
    ):
        raise RuntimeError("strict bind collision did not fail before a listener report or ownership check")

    gateway_status = REFERENCE.private_gateway_status(main_checkout, gateway_root)
    routes = {route.get("domain"): route for route in gateway_status.get("routes", [])}
    if collision_domain in routes:
        raise RuntimeError("failed collision child published a route to the foreign listener")
    foreign_route = routes.get(foreign_api["route_domain"])
    if not foreign_route or foreign_route.get("target") != foreign_api["address"]:
        raise RuntimeError("partial failure removed or retargeted the unaffected foreign API route")
    if not address_accepts_connection(foreign_api["address"]):
        raise RuntimeError("partial failure stopped the foreign listener that occupied the requested port")
    ca_context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
    code, _, _ = REFERENCE.gateway_request(
        foreign_api["route_domain"], gateway_port, ca_context, "/v1/health",
        {"Host": f"{foreign_api['route_domain']}:{gateway_port}"},
    )
    if code != 200:
        raise RuntimeError(f"foreign API HTTPS route returned {code} after the failed child launch")

    affected_after = {}
    for name, before in main_states.items():
        owner_path = main_checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json"
        after = json.loads(owner_path.read_text(encoding="utf-8"))
        affected_after[name] = after.get("status")
        if after.get("route_owner") or after.get("status") not in {"stopped", "unavailable"}:
            raise RuntimeError(f"partial failure left main-scope {name} in an uncertain or published state")
        if address_accepts_connection(before["address"]):
            raise RuntimeError(f"partial failure left main-scope listener {name} accepting connections")

    for name, before in foreign_states.items():
        _, after = REFERENCE.managed_listener_state(foreign_checkout, name)
        if after["generation"] != before["generation"] or after["address"] != before["address"]:
            raise RuntimeError(f"partial failure changed foreign worktree listener {name}")
        if not address_accepts_connection(after["address"]):
            raise RuntimeError(f"partial failure stopped foreign worktree listener {name}")

    receipt = {
        "status": "passed",
        "command": command_receipt,
        "command_exit": result.returncode,
        "diagnostic": diagnostic,
        "runtime_spec_bind": listener_spec.get("bind"),
        "child_bind_error": child_errors,
        "collision_domain_absent": True,
        "foreign_address": foreign_api["address"],
        "foreign_route": foreign_api["route_domain"],
        "foreign_https_status": code,
        "failed_scope_listener_states": affected_after,
        "other_worktree_listeners_survived": True,
        "failed_scope_runtime_capture": capture_runtime_evidence(
            main_checkout, ["api", "front", "admin", "collision-probe"],
            Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]),
            "after-occupied-port-failure",
        ),
        "scope_down_before_collision": down_before,
        "stopped_applications_before_collision": stopped_before,
        "foreign_runtime_capture": capture_runtime_evidence(
            foreign_checkout, ["api", "front", "admin"],
            Path(env["UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT"]),
            "foreign-worktree-after-occupied-port-failure",
        ),
    }
    collision_down = effigy_json(EFFIGY, main_checkout, env, "container", "hybrid", "down", "--json", timeout=300)
    stopped_collision = json.loads(state_path.read_text(encoding="utf-8"))
    collision_reconciliation = verify_failed_scope_reconciled(main_checkout, gateway_root, env)
    routes_after_down = {
        route.get("domain") for route in
        REFERENCE.private_gateway_status(main_checkout, gateway_root).get("routes", [])
    }
    if collision_domain in routes_after_down:
        raise RuntimeError("collision probe route remained after exact-scope down")
    if not address_accepts_connection(foreign_api["address"]):
        raise RuntimeError("exact-scope collision down stopped the foreign listener")
    receipt["collision_scope_down"] = collision_down
    receipt["collision_state_after_down"] = {
        "status": stopped_collision.get("status"),
        "route_owner": stopped_collision.get("route_owner"),
    }
    receipt["collision_scope_reconciliation"] = collision_reconciliation
    manifest_path.write_text(original_manifest, encoding="utf-8")
    recovery, recovered_states = recover_reference_apps(
        main_checkout, original_manifest, env, gateway_port,
        "after-occupied-port-collision-recovery",
    )
    receipt["scope_recovery"] = recovery
    print("PASS strict occupied-port launch failed closed; no collision route was published; "
          "foreign process/route and both other Reference scopes survived", flush=True)
    return receipt, recovered_states


def install_public_origin_fixture(checkout: Path) -> None:
    REFERENCE.install_public_origin_hooks([checkout])
    REFERENCE.install_origin_probe(checkout)


def service_shell(binary: str, checkout: Path, env: dict[str, str], command: str,
                  timeout: int = 90, print_output: bool = True) -> str:
    result = run([binary, "--repo", str(checkout), "container", "hybrid", "shell",
                  "--service", "minio", "--command", command],
                 cwd=checkout, env=env, timeout=timeout, print_output=print_output)
    return result.stdout


def _s3_request(port: int, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, str], bytes]:
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    short_date = now.strftime("%Y%m%d")
    host = f"127.0.0.1:{port}"
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    scope = f"{short_date}/us-east-1/s3/aws4_request"
    canonical_request = "\n".join((
        method,
        path,
        "",
        canonical_headers,
        signed_headers,
        payload_hash,
    ))
    string_to_sign = "\n".join((
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ))

    def sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode(), hashlib.sha256).digest()

    signing_key = sign(b"AWS4minioadmin", short_date)
    signing_key = sign(signing_key, "us-east-1")
    signing_key = sign(signing_key, "s3")
    signing_key = sign(signing_key, "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Host": host,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Date": amz_date,
        "Authorization": (
            "AWS4-HMAC-SHA256 Credential=minioadmin/" + scope +
            f", SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        connection.close()


def prove_minio(checkout: Path, env: dict[str, str], minio_port: int, allowed_origin: str) -> None:
    minio_version = service_shell(EFFIGY, checkout, env, "minio --version")
    mc_version = service_shell(EFFIGY, checkout, env, "mc --version")
    if IMAGE not in (checkout / "infra/dev/catalog/minio/compose.fragment.yml").read_text(encoding="utf-8"):
        raise RuntimeError("fixture MinIO catalog override is missing the source-built local image")
    if "RELEASE.2025-09-07T16-13-09Z" not in minio_version or "RELEASE.2025-08-13T08-35-41Z" not in mc_version:
        raise RuntimeError("the running catalog service did not expose the pinned MinIO and mc releases")
    with socket.create_connection(("127.0.0.1", minio_port), timeout=10):
        pass
    print(f"PASS host loopback reached the source-built MinIO API listener 127.0.0.1:{minio_port}", flush=True)
    service_shell(EFFIGY, checkout, env, "mc ready local")
    bucket = "underlay-reference-qualification"
    service_shell(EFFIGY, checkout, env, f"mc mb local/{bucket} --ignore-existing")
    payload = "underlay-reference-source-pinned-minio-proof"
    service_shell(EFFIGY, checkout, env, f"printf %s {json.dumps(payload)} | mc pipe local/{bucket}/probe.txt")
    mc_put_status, _, received = _s3_request(
        minio_port, "GET", f"/{bucket}/probe.txt",
    )
    if mc_put_status != 200 or received.decode("utf-8") != payload:
        raise RuntimeError(
            f"mc PUT followed by host-signed S3 GET returned HTTP {mc_put_status} or changed bytes"
        )
    cors_connection = http.client.HTTPConnection("127.0.0.1", minio_port, timeout=10)
    try:
        cors_connection.request(
            "OPTIONS", f"/{bucket}/cors-probe",
            headers={
                "Origin": allowed_origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,x-amz-content-sha256,x-amz-date",
            },
        )
        cors_response = cors_connection.getresponse()
        cors_headers = {key.lower(): value for key, value in cors_response.getheaders()}
        cors_response.read()
        if cors_headers.get("access-control-allow-origin") != allowed_origin:
            raise RuntimeError("MinIO did not allow the configured disposable browser origin")
        if "PUT" not in cors_headers.get("access-control-allow-methods", "").upper():
            raise RuntimeError("MinIO CORS preflight did not allow the S3 PUT method")
        allowed_headers = cors_headers.get("access-control-allow-headers", "").lower()
        if not all(header in allowed_headers for header in ("authorization", "x-amz-content-sha256", "x-amz-date")):
            raise RuntimeError("MinIO CORS preflight did not allow the signed S3 request headers")
        print("PASS source-built MinIO server-level CORS preflight for the exact browser origin, PUT, and signed headers",
              flush=True)
    finally:
        cors_connection.close()

    payload = b"host-signed-reference-minio-loopback-proof"
    object_path = f"/{bucket}/probe.txt"
    put_status, _, _ = _s3_request(minio_port, "PUT", object_path, payload)
    if put_status not in (200, 201):
        raise RuntimeError(f"host-signed MinIO object PUT returned HTTP {put_status}")
    get_status, _, received = _s3_request(minio_port, "GET", object_path)
    if get_status != 200 or received != payload:
        raise RuntimeError(f"host-signed MinIO object GET returned HTTP {get_status} or changed bytes")
    delete_status, _, _ = _s3_request(minio_port, "DELETE", object_path)
    if delete_status not in (200, 204):
        raise RuntimeError(f"host-signed MinIO object DELETE returned HTTP {delete_status}")
    print(f"PASS host-to-MinIO signed S3 PUT/GET/DELETE through 127.0.0.1:{minio_port}", flush=True)
    service_shell(EFFIGY, checkout, env, f"mc rb local/{bucket}")
    print(f"PASS source-built MinIO catalog health, pinned versions and CORS for {allowed_origin}", flush=True)


def observe_routes(checkout: Path, gateway_root: Path, env: dict[str, str],
                   states: dict[str, dict], gateway_port: int) -> None:
    status = json.loads(run([EFFIGY, "--json", "gateway", "status", "--private-state-root", str(gateway_root)],
                            env=env, print_output=False).stdout)["result"]
    ca = gateway_root / "ca/rootCA.pem"
    context = ssl.create_default_context(cafile=str(ca))
    routes = {route["domain"]: route for route in status.get("routes", [])}
    for name in ("api", "front", "admin"):
        state = states[name]
        domain = state["route_domain"]
        route = routes.get(domain)
        if not route or route.get("target") != state["address"] or route.get("cert_ready") is not True:
            raise RuntimeError(f"Effigy route for {name} was not ready at the owned listener address")
        path = "/v1/health" if name == "api" else "/"
        code, _, _ = REFERENCE.gateway_request(domain, gateway_port, context, path,
                                               {"Host": f"{domain}:{gateway_port}"})
        if code != 200:
            raise RuntimeError(f"verified private HTTPS route for {name} returned {code}")
    print("PASS actual Reference API/front/admin listeners and CA-verified private HTTPS routes", flush=True)

    for name in ("front", "admin"):
        domain = states[name]["route_domain"]
        origin = f"https://{domain}:{gateway_port}"
        path = "/__qualification/origin?probe=public-origin"
        code, _, body = REFERENCE.gateway_request(domain, gateway_port, context, path,
                                                   {"Host": f"{domain}:{gateway_port}", "Origin": origin})
        result = json.loads(body)
        print(f"Reference {name}: path={result.get('requestPath')} Host={result.get('host')} "
              f"Origin={result.get('origin')} forwarded-proto={result.get('forwardedProto')} "
              f"forwarded-host={result.get('forwardedHost')} event-origin={result.get('urlOrigin')} "
              f"request-origin={result.get('requestUrlOrigin')}", flush=True)
        if code != 200 or result.get("urlOrigin") != origin or result.get("requestUrlOrigin") != origin:
            raise RuntimeError(f"actual Reference {name} hook did not expose the configured HTTPS origin coherently")
        if result.get("requestPath") != "/__qualification/origin" or result.get("requestSearch") != "?probe=public-origin":
            raise RuntimeError(f"actual Reference {name} hook changed the request path or query")
    print("PASS actual Reference front/admin event.url and request.url use configured HTTPS origins", flush=True)

    for name in ("front", "admin"):
        domain = states[name]["route_domain"]
        client_status, _, body = REFERENCE.gateway_request(domain, gateway_port, context, "/@vite/client")
        if client_status != 200:
            raise RuntimeError(f"Reference {name} Vite client returned {client_status}")
        client = body.decode("utf-8", errors="replace")
        match = re.search(r"(?:wsToken|token)\s*[:=]\s*['\"]([^'\"]*)['\"]", client)
        token = match.group(1) if match else ""
        if str(gateway_port) not in client or "wss" not in client:
            raise RuntimeError(f"Reference {name} Vite client did not advertise the gateway's wss endpoint")
        ws = REFERENCE.gateway_websocket_upgrade(domain, gateway_port, context, token)
        if ws != 101:
            raise RuntimeError(f"Reference {name} HMR WebSocket upgrade returned {ws}")
    print(f"PASS front/admin Vite HMR WebSockets upgraded with 101 through gateway port {gateway_port}", flush=True)


def prove_minio_gateway_route(checkout: Path, gateway_root: Path, domains: dict[str, str], gateway_port: int) -> dict:
    domain = domains["s3"]
    status = REFERENCE.private_gateway_status(checkout, gateway_root)
    registered_domains = sorted(
        item.get("domain") for item in status.get("routes", [])
        if isinstance(item.get("domain"), str)
    )
    route = next((item for item in status.get("routes", []) if item.get("domain") == domain), None)
    if route is None:
        return {"status": "unavailable", "phase": "route_registration",
                "domain": domain, "route_registered": False,
                "registered_domains": registered_domains}
    if route.get("tls") is not True or not route.get("target"):
        return {"status": "unavailable", "phase": "route_configuration",
                "domain": domain, "route_registered": True,
                "tls": route.get("tls"), "route_target_present": bool(route.get("target"))}
    if route.get("cert_ready") is not True:
        return {"status": "unavailable", "phase": "certificate_readiness",
                "domain": domain, "tls": route.get("tls"),
                "route_target_present": bool(route.get("target")),
                "cert_ready": route.get("cert_ready")}

    cert_path = gateway_root / "certs" / f"{domain}.pem"
    ca_path = gateway_root / "ca/rootCA.pem"
    if not cert_path.is_file() or not ca_path.is_file():
        return {"status": "unavailable", "phase": "private_certificate_or_ca_missing",
                "domain": domain, "cert_present": cert_path.is_file(), "ca_present": ca_path.is_file()}
    certificate = ssl._ssl._test_decode_cert(str(cert_path))
    dns_sans = {value.lower() for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"}
    if domain.lower() not in dns_sans:
        return {"status": "unavailable", "phase": "certificate_san_mismatch",
                "domain": domain, "dns_sans": sorted(dns_sans)}

    context = ssl.create_default_context(cafile=str(ca_path))
    try:
        code, _, _ = REFERENCE.gateway_request(
            domain,
            gateway_port,
            context,
            "/minio/health/ready",
            {"Host": f"{domain}:{gateway_port}"},
        )
    except ssl.SSLError as error:
        return {"status": "unavailable", "phase": "verified_ca_sni_handshake",
                "domain": domain, "route_tls": route.get("tls"),
                "cert_ready": route.get("cert_ready"), "dns_sans": sorted(dns_sans),
                "error_type": type(error).__name__, "error": str(error)[:400]}
    if code != 200:
        return {"status": "unavailable", "phase": "private_https_route_response",
                "domain": domain, "http_status": code, "route_tls": route.get("tls"),
                "cert_ready": route.get("cert_ready"), "dns_sans": sorted(dns_sans)}
    print(f"PASS source-built MinIO private HTTPS/SNI route {domain}:{gateway_port} readiness returned 200", flush=True)
    return {"status": "passed", "domain": domain, "http_status": code,
            "route_target": route.get("target"), "cert_ready": True, "dns_sans": sorted(dns_sans)}


def main() -> int:
    global EFFIGY
    EFFIGY = require_effigy_binary()
    REFERENCE.EFFIGY = EFFIGY
    source = REFERENCE.DEFAULT_REFERENCE.resolve(strict=True)
    os.environ["UNDERLAY_REFERENCE_SOURCE"] = str(source)
    source = REFERENCE.reference_source()
    fixture_root = mktemp_root()
    print(f"PRIVATE REFERENCE RUNTIME ROOT: {fixture_root}", flush=True)
    private_home = fixture_root / "home"
    private_home.mkdir(mode=0o700)
    private_cargo_home = private_home / ".cargo"
    private_cargo_home.mkdir(mode=0o700)
    private_cargo_target = private_home / ".cargo-target"
    private_cargo_target.mkdir(mode=0o700)
    colima_home = fixture_root / "colima-home"
    colima_home.mkdir(mode=0o700)
    expected_colima_socket = colima_home / "_lima/colima-effigy/ssh.sock.1234567890123456"
    if len(str(expected_colima_socket)) >= 104:
        raise RuntimeError("private Colima socket path would exceed the host Unix socket limit")
    gateway_root = fixture_root / "gateway"
    gateway_root.mkdir(mode=0o700)
    runtime_env = os.environ.copy()
    real_home = runtime_env.get("HOME", str(Path.home()))
    runtime_env.update({
        "HOME": str(private_home),
        "COLIMA_HOME": str(colima_home),
        "EFFIGY_COMPOSE_BACKEND": "colima",
        "EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": str(gateway_root),
        "UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(fixture_root),
    })
    runtime_env["RUSTUP_HOME"] = runtime_env.get("RUSTUP_HOME") or str(Path(real_home) / ".rustup")
    runtime_env["CARGO_HOME"] = str(private_cargo_home)
    # Let Cargo manage one isolated host target for these identical, sequential
    # Reference clones. This is the standard Cargo build directory, not a
    # second cache manager, and remains separate from the container image.
    runtime_env["CARGO_TARGET_DIR"] = str(private_cargo_target)
    receipts: dict[str, object] = {
        "effigy_source": "2f7b1819fd0e72afff18a6053be424719ecf71fc",
        "effigy_binary": EFFIGY,
        "effigy_binary_sha256": "2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc",
        "reference_source": subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                           capture_output=True, text=True, check=True).stdout.strip(),
        "fixture_root": str(fixture_root),
        "instances": [],
        "cleanup": [],
    }
    started: list[Path] = []
    gateway_ready = False
    gateway_attempted = False
    profile_started = False
    default_started = False
    default_scope_started = False
    default_scope_stopped = False
    consumer_baselines: dict[Path, dict[str, bytes | None]] = {}
    catalog_baselines: dict[Path, dict[str, str]] = {}
    domains_by_checkout: dict[Path, dict[str, str]] = {}
    declared_domains_by_checkout: dict[Path, dict[str, str]] = {}
    all_states: list[tuple[Path, dict[str, dict]]] = []
    states_by_checkout: dict[Path, dict[str, dict]] = {}
    uncertain_checkouts: set[Path] = set()
    hybrid_down_verified: set[Path] = set()
    hybrid_scopes_retired: set[Path] = set()
    try:
        phase = "private gateway TLS"
        gateway_json(EFFIGY, runtime_env, gateway_root, "setup-tls")
        gateway_attempted = True
        gateway_status = gateway_json(EFFIGY, runtime_env, gateway_root, "up",
                                      "--dns-addr", "127.0.0.1:0",
                                      "--proxy-addr", "127.0.0.1:0",
                                      "--https-addr", "127.0.0.1:0")
        gateway_ready = True
        if gateway_status.get("private") is not True or gateway_status.get("running") is not True:
            raise RuntimeError("private gateway did not report a running isolated instance")
        gateway_port = int(gateway_status["https_addr"].rsplit(":", 1)[1])
        if gateway_status.get("tls", {}).get("ca_installed") is not False:
            raise RuntimeError("private gateway unexpectedly reports installed trust")
        receipts["gateway"] = {"private": True, "https_addr": gateway_status["https_addr"],
                                "ca_installed": False}

        phase = "private Colima profile and source-pinned MinIO image"
        run(["colima", "start", "--profile", "effigy", "--runtime", "containerd",
             "--cpu", "6", "--memory", "8", "--disk", "64"], env=runtime_env,
            timeout=1200)
        profile_started = True
        image = prepare_source_image(fixture_root, runtime_env)
        receipts["minio_image"] = image

        phase = "private Reference main plus two worktrees"
        # Colima mounts the task-private HOME into its guest. Keep the cloned
        # Reference checkouts under that mount so the guest-side Compose client
        # can read Effigy's generated file and bind-mounted workspace paths.
        reference_root = private_home / "reference"
        reference_root.mkdir(mode=0o700)
        checkouts = REFERENCE.make_reference_instances(source, reference_root)
        for checkout in checkouts:
            REFERENCE.point_bundle_at_task_branch(checkout)
        receipts["fixture_secrets"] = REFERENCE.initialize_reference_fixture_secrets(checkouts, runtime_env)
        REFERENCE.prove_worktree_plans(checkouts)
        for checkout in checkouts:
            consumer_baselines[checkout] = baseline_consumer_files(checkout)
            bundle = json.loads(run([EFFIGY, "--repo", str(checkout), "bundle", "inspect", "--json"],
                                    cwd=checkout, env=runtime_env, timeout=120,
                                    print_output=False).stdout)["result"]
            if bundle["source"]["source_type"] != "path" or Path(bundle["source"]["source_path"]).resolve() != REPO.resolve():
                raise RuntimeError("private Reference assembly did not resolve this bundle branch")
            host_map = effigy_json(EFFIGY, checkout, runtime_env, "container", "hosts", "--json")
            domains_by_checkout[checkout] = route_domains(host_map)
            declared_domains_by_checkout[checkout] = declared_route_domains(host_map)
            cors_origin = f"https://{domains_by_checkout[checkout]['front']}:{gateway_port}"
            catalog_baselines[checkout] = {
                "minio": install_minio_catalog_override(
                    EFFIGY, checkout, runtime_env, cors_origin=cors_origin,
                ),
                **install_dynamic_loopback_service_ports(EFFIGY, checkout, runtime_env),
            }
            install_public_origin_fixture(checkout)
            domains = domains_by_checkout[checkout]
            services = REFERENCE.manifest_section((checkout / "effigy.toml").read_text(encoding="utf-8"), "bundle.sources")
            if "siblings = false" not in services:
                raise RuntimeError("Reference private assembly enabled sibling sources")
            prepared = run([EFFIGY, "--repo", str(checkout), "workspace:js:prepare"],
                           cwd=checkout, env=runtime_env, timeout=900, print_output=False)
            if prepared.returncode != 0:
                raise RuntimeError("private Reference workspace preparation did not exit successfully")
            receipts["instances"].append({"path": str(checkout), "domains": domains,
                                           "dns_route_declarations": declared_domains_by_checkout[checkout],
                                           "workspace_prepare": "exit 0"})

        phase = "hybrid service startup"
        for index, checkout in enumerate(checkouts):
            names = domains_by_checkout[checkout]
            project = f"underlay-reference-qualification-{index}"
            append_hybrid_services(checkout, declared_domains_by_checkout[checkout], project)
            started.append(checkout)
            result = effigy_json(EFFIGY, checkout, runtime_env, "container", "hybrid", "up", "--detach", "--json")
            receipts["instances"][index]["service_up"] = result

        for index, checkout in enumerate(checkouts):
            status = effigy_json(EFFIGY, checkout, runtime_env, "container", "hybrid", "status", "--json")
            services = {item["name"]: item["status"] for item in status.get("services", [])}
            for required in ("postgres", "mailpit", "minio"):
                if services.get(required) != "Up":
                    raise RuntimeError(f"Reference {index} service {required} is not Up: {services.get(required)}")
            compose = (checkout / status["compose_file"]).read_text(encoding="utf-8")
            if "workspace-rust-bun" in compose:
                raise RuntimeError("hybrid service fixture unexpectedly depends on the workspace Rust/Bun image")
            up_report = receipts["instances"][index]["service_up"]
            pg_port = service_host_port_from_up(up_report, compose, 5432)
            smtp_port = service_host_port_from_up(up_report, compose, 1025)
            minio_port = service_host_port_from_up(up_report, compose, 9000)
            if not pg_port or not smtp_port or not minio_port:
                raise RuntimeError("Reference service host map omitted loopback Postgres/SMTP/MinIO endpoints")
            service_readiness = [
                wait_loopback_service(pg_port, "postgres"),
                wait_loopback_service(smtp_port, "mailpit"),
                wait_loopback_service(minio_port, "minio"),
            ]
            receipts["instances"][index]["service_readiness"] = service_readiness
            print(f"PASS Reference {index} Postgres/Mailpit/MinIO loopback readiness: "
                  f"{[(item['service'], item['endpoint'], item['result']) for item in service_readiness]}",
                  flush=True)
            names = route_domains(effigy_json(EFFIGY, checkout, runtime_env, "container", "hosts", "--json"))
            configure_app_urls(checkout, names, pg_port, gateway_port)
            append_reference_host_processes(checkout, names, gateway_port, minio_port, REPO)
            # The same private project is reconciled after actual service ports are known.
            # Effigy adds its owned host children; it retains the already-running service resources.
            phase = f"Reference {index} managed host listener startup and readiness"
            result = hybrid_up_with_declared_task_secrets(checkout, runtime_env)
            receipts["instances"][index]["service_endpoints"] = {
                "postgres": f"127.0.0.1:{pg_port}", "smtp": f"127.0.0.1:{smtp_port}",
                "minio": f"127.0.0.1:{minio_port}",
            }
            receipts["instances"][index]["app_up"] = result

        phase = "three-instance listener and service proof"
        all_addresses: list[str] = []
        all_domains: list[str] = []
        service_ports: dict[str, list[int]] = {"postgres": [], "smtp": [], "minio": []}
        for index, checkout in enumerate(checkouts):
            states: dict[str, dict] = {}
            for name in ("api", "front", "admin"):
                _, state = REFERENCE.managed_listener_state(checkout, name)
                states[name] = state
                all_addresses.append(state["address"])
                all_domains.append(state["route_domain"])
            stack = effigy_json(
                EFFIGY, checkout, runtime_env, "container", "hybrid", "status", "--json",
            )
            live_services = {item.get("name"): item.get("status")
                             for item in stack.get("services", [])}
            if any(live_services.get(name) != "Up" for name in ("postgres", "mailpit", "minio")):
                raise RuntimeError(f"Reference {index} service status changed after host startup: {live_services}")
            endpoints = receipts["instances"][index].get("service_endpoints", {})
            pg = port_from_loopback_endpoint(endpoints, "postgres")
            smtp = port_from_loopback_endpoint(endpoints, "smtp")
            minio_port = port_from_loopback_endpoint(endpoints, "minio")
            if pg is None or smtp is None or minio_port is None:
                raise RuntimeError("Reference stack omitted a loopback service endpoint")
            service_ports["postgres"].append(pg)
            service_ports["smtp"].append(smtp)
            service_ports["minio"].append(minio_port)
            with smtplib.SMTP("127.0.0.1", smtp, timeout=5) as client:
                code, _ = client.ehlo("qualification.invalid")
                if not 200 <= code < 300:
                    raise RuntimeError(f"SMTP EHLO returned {code}")
            api_log = checkout / ".effigy/runtime/host-processes/hybrid/effigy/api.log"
            if "sqlx::postgres::notice" not in api_log.read_text(encoding="utf-8", errors="replace"):
                raise RuntimeError("Reference host API did not report Postgres migration activity")
            observe_routes(checkout, gateway_root, runtime_env, states, gateway_port)
            prove_minio(
                checkout,
                runtime_env,
                minio_port,
                f"https://{states['front']['route_domain']}:{gateway_port}",
            )
            instance_domains = route_domains(effigy_json(EFFIGY, checkout, runtime_env, "container", "hosts", "--json"))
            minio_gateway_route = prove_minio_gateway_route(
                checkout, gateway_root, instance_domains, gateway_port,
            )
            receipts["instances"][index]["minio_gateway_route"] = minio_gateway_route
            if minio_gateway_route.get("status") != "passed":
                receipts.setdefault("unavailable_proofs", []).append({
                    "checkout": str(checkout), "proof": "MinIO HTTPS/SNI gateway route",
                    **minio_gateway_route,
                })
                print(f"BLOCKED private MinIO TLS/SNI route: {minio_gateway_route}", flush=True)
            all_states.append((checkout, states))
            states_by_checkout[checkout] = states
        if len(set(all_addresses)) != 9 or len(set(all_domains)) != 9:
            raise RuntimeError("the three Reference identities did not own nine distinct listeners/routes")
        if any(len(set(ports)) != 3 for ports in service_ports.values()):
            raise RuntimeError(f"isolated Reference services did not receive distinct host ports: {service_ports}")
        receipts["three_instance_addresses"] = all_addresses
        receipts["three_instance_routes"] = all_domains
        receipts["three_instance_service_ports"] = service_ports
        receipts["initial_runtime_captures"] = [
            capture_runtime_evidence(checkout, ["api", "front", "admin"], fixture_root,
                                     f"three-instance-{index}")
            for index, (checkout, _) in enumerate(all_states)
        ]
        print("PASS three simultaneous Reference checkout identities own nine distinct ready listeners/routes", flush=True)

        phase = "guarded API child restart"
        main_checkout, main_states = all_states[0]
        restart_before = main_states["api"]
        restart_passed = False
        restart_error = None
        restart_diagnostic = None
        try:
            restart_passed = REFERENCE.prove_reference_api_restart(
                main_checkout, gateway_root, main_states,
            )
            restart_diagnostic = REFERENCE.LAST_API_RESTART_DIAGNOSTIC
        except Exception as error:
            restart_error = f"{type(error).__name__}: {error}"
            restart_diagnostic = REFERENCE.LAST_API_RESTART_DIAGNOSTIC
            print(f"BLOCKED guarded API restart proof: {restart_error}", flush=True)
        api_state_path = (
            main_checkout / ".effigy/runtime/host-processes/hybrid/effigy/api.listener.json"
        )
        after = json.loads(api_state_path.read_text(encoding="utf-8"))
        api_ready_after_probe = after.get("status") == "ready" and bool(after.get("route_owner"))
        if api_ready_after_probe:
            refreshed_states = {
                name: REFERENCE.managed_listener_state(main_checkout, name)[1]
                for name in ("api", "front", "admin")
            }
        else:
            refreshed_states = main_states
            restart_passed = False
            restart_error = restart_error or (
                f"API listener owner state ended {after.get('status')!r} without a ready route owner"
            )
            print(
                "UNPROVEN API restart left the recorded generation unavailable; preserving its failed-state "
                "receipt and proceeding to exact-scope recovery with no additional PID signal",
                flush=True,
            )
        generation_changed = after.get("generation") != restart_before["generation"]
        restart_passed = restart_passed and generation_changed and api_ready_after_probe
        receipts["api_restart"] = {
            "status": "passed" if restart_passed else "unproven",
            "before_generation": restart_before["generation"],
            "after_generation": after.get("generation"),
            "before_address": restart_before["address"],
            "after_address": after.get("address"),
            "after_status": after.get("status"),
            "after_route_owner": after.get("route_owner"),
            "guarded_restart_function_returned_pass": restart_passed,
            "error": restart_error,
            "diagnostic": restart_diagnostic,
        }
        if not restart_passed:
            receipts.setdefault("unavailable_proofs", []).append({
                "proof": "Reference API child restart, route replacement, and dependent propagation",
                "status": "unproven",
                "phase": "guarded API child restart",
                "before_generation": restart_before["generation"],
                "after_generation": after.get("generation"),
                "before_address": restart_before["address"],
                "after_address": after.get("address"),
                "after_status": after.get("status"),
                "after_route_owner": after.get("route_owner"),
                "error": restart_error,
                "diagnostic": restart_diagnostic,
            })
            print("UNPROVEN API child restart/route propagation", flush=True)
        if not api_ready_after_probe:
            receipts.setdefault("unavailable_proofs", []).extend([
                {
                    "proof": "interrupted unready-child startup reconciliation",
                    "status": "not_attempted",
                    "reason": "the guarded restart left the main API without a ready owner; no new host startup was attempted",
                },
                {
                    "proof": "occupied-port partial failure and foreign-resource survival",
                    "status": "not_attempted",
                    "reason": "the main Reference scope was not ready for a bounded collision trial",
                },
                {
                    "proof": "isolated teardown with two active sibling instances",
                    "status": "not_attempted",
                    "reason": "the main Reference scope did not retain a ready application set after restart",
                },
            ])
            raise RuntimeError(
                "guarded API restart left no ready owner; withholding further host-start and isolation probes"
            )
        receipts["api_restart_runtime_capture"] = capture_runtime_evidence(
            main_checkout, ["api", "front", "admin"], fixture_root, "after-api-restart",
        )
        main_states = refreshed_states
        all_states[0] = (main_checkout, main_states)
        states_by_checkout[main_checkout] = main_states

        # Exercise interruption and collision in an untouched worktree scope.
        # The guarded SIGKILL restart above intentionally changes the main API
        # generation; do not use that restarted supervisor as the control for
        # unrelated start/failure tests.
        lifecycle_checkout, lifecycle_states = all_states[1]
        lifecycle_survivors = [all_states[0], all_states[2]]
        phase = "interrupted readiness startup and exact-scope recovery"
        interruption, lifecycle_states = prove_interrupted_startup(
            lifecycle_checkout, lifecycle_states, lifecycle_survivors,
            gateway_root, gateway_port, runtime_env,
        )
        receipts["interruption_recovery"] = interruption
        if interruption.get("status") != "passed":
            receipts.setdefault("unavailable_proofs", []).append({
                "proof": "interrupt an unready managed host child and reconcile only its recorded scope",
                "status": "unproven",
                "phase": "interrupted readiness startup",
                "command_exit": interruption.get("interrupted_effigy_command_exit"),
                "command_error": interruption.get("command_error"),
                "ready_check_observed_503": interruption.get("ready_check_observed_503_before_interrupt"),
                "child_state_after_reconcile": interruption.get("interrupted_state_after_reconcile"),
                "route_absent": interruption.get("interrupted_route_absent"),
            })
        all_states[1] = (lifecycle_checkout, lifecycle_states)
        states_by_checkout[lifecycle_checkout] = lifecycle_states

        phase = "occupied-port partial-launch isolation"
        partial_failure, lifecycle_states = prove_failed_collision_is_scoped(
            lifecycle_checkout, lifecycle_states, all_states[2][0], all_states[2][1],
            gateway_root, gateway_port, runtime_env,
        )
        receipts["partial_failure"] = partial_failure
        if receipts["partial_failure"].get("status") != "passed":
            receipts["owner_uncertainty"] = True
            uncertain_checkouts.add(lifecycle_checkout)
            receipts.setdefault("unavailable_proofs", []).append({
                "proof": "Reference strict occupied-port failure with retained failed-generation ownership diagnostic",
                "status": "unproven",
                "phase": "occupied-port partial-launch isolation",
                **receipts["partial_failure"],
            })
            raise RuntimeError("collision failure state was not retained; preserving the private runtime scope")
        all_states[1] = (lifecycle_checkout, lifecycle_states)
        states_by_checkout[lifecycle_checkout] = lifecycle_states
        receipts["partial_failure"]["additional_main_instance_survival"] = assert_foreign_instances_live(
            [all_states[0]], gateway_root, gateway_port,
        )

        phase = "isolated worktree teardown while main and second worktree remain live"
        isolation = verify_scope_down(
            lifecycle_checkout,
            lifecycle_states,
            gateway_root,
            gateway_port,
            gateway_root / "ca/rootCA.pem",
            [all_states[0], all_states[2]],
            runtime_env,
        )
        receipts["isolated_worktree_teardown"] = isolation
        print("PASS one worktree scope down withdrew its listeners/routes while main and the other worktree remained ready", flush=True)

        phase = "retire remaining hybrid fixture scopes before default startup"
        for checkout, states in all_states:
            down = effigy_json(EFFIGY, checkout, runtime_env, "container", "hybrid", "down", "--json", timeout=300)
            receipts["cleanup"].append({"checkout": str(checkout), "hybrid_down_before_default": down})
            receipts["cleanup"].append({"checkout": str(checkout),
                                        "hybrid_stopped_before_default": verify_stopped_scope(checkout, states, gateway_root)})
            hybrid_down_verified.add(checkout)
            declarations = declared_host_processes(checkout)
            reconciled = verify_failed_scope_reconciled(checkout, gateway_root, runtime_env) if declarations else None
            receipts["cleanup"].append({"checkout": str(checkout),
                                        "hybrid_scope_reconciled_before_retire": reconciled})
            retired = effigy_json(EFFIGY, checkout, runtime_env, "container", "retire", "--yes", "--json", timeout=300)
            receipts["cleanup"].append({"checkout": str(checkout), "hybrid_scope_retire_before_default": retired})
            empty_verified_scope = (
                retired.get("idempotent") is True
                and retired.get("scope") is None
                and not retired.get("removed")
                and not retired.get("remaining")
                and not retired.get("unverified_profiles")
                and reconciled is not None
            )
            if ((retired.get("record_removed") is not True and not empty_verified_scope)
                    or retired.get("unverified_profiles")):
                raise RuntimeError(f"exact hybrid checkout scope did not retire cleanly: {checkout.name}")
            hybrid_scopes_retired.add(checkout)

        phase = "private default container build and startup"
        occupied = fixed_default_ports_available()
        if occupied:
            raise RuntimeError(f"default container fixed host ports are occupied; startup was held safely: {occupied}")
        restore_consumer_defaults(main_checkout, consumer_baselines[main_checkout])
        restore_default_catalogs(main_checkout, catalog_baselines[main_checkout])
        default_started = True
        default_up = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "up", "--detach", "--json", timeout=5400)
        default_scope_started = True
        default_status = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "status", "--json", timeout=120)
        default_services = {item["name"]: item["status"] for item in default_status.get("services", [])}
        receipts["default_container_startup"] = {
            "up": default_up,
            "services": default_services,
            "compose_file": default_status.get("compose_file"),
            "workspace_rust_bun_mapping": None,
            "minio_override": IMAGE,
            "published_minio_pull_proven": False,
        }
        if not default_services or any(value != "Up" for value in default_services.values()):
            raise RuntimeError(f"default container stack did not reach all-Up status: {default_services}")
        default_compose_path = Path(default_status["compose_file"])
        if not default_compose_path.is_absolute():
            default_compose_path = main_checkout / default_compose_path
        default_compose = default_compose_path.read_text(encoding="utf-8")
        workspace_service = re.search(
            r"(?ms)^  workspace:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", default_compose
        )
        dockerfile_match = re.search(
            r"(?m)^      dockerfile: (.+)$", workspace_service.group(1)
        ) if workspace_service else None
        workspace_dockerfile = (
            (main_checkout / dockerfile_match.group(1)).resolve()
            if dockerfile_match else None
        )
        dockerfile_text = workspace_dockerfile.read_text(encoding="utf-8") if (
            workspace_dockerfile and workspace_dockerfile.is_file()
        ) else ""
        workspace_mapping = 'catalog = "workspace-rust-bun"' in (REPO / "export.toml").read_text(encoding="utf-8")
        receipts["default_container_startup"].update({
            "compose_sha256": hashlib.sha256(default_compose.encode()).hexdigest(),
            "workspace_service_present": workspace_service is not None,
            "workspace_service_has_build": bool(workspace_service and "build:" in workspace_service.group(1)),
            "workspace_rust_bun_mapping": workspace_mapping,
            "workspace_dockerfile": str(workspace_dockerfile) if workspace_dockerfile else None,
            "workspace_dockerfile_sha256": hashlib.sha256(dockerfile_text.encode()).hexdigest()
                if dockerfile_text else None,
            "workspace_toolchain_markers": {
                marker: marker in dockerfile_text for marker in ("FROM rust:", "ARG BUN_VERSION", "BUN_INSTALL")
            },
            "minio_image_in_compose": IMAGE in default_compose,
        })
        if not receipts["default_container_startup"]["workspace_service_has_build"]:
            raise RuntimeError("default stack did not generate its built workspace service")
        if not dockerfile_match or not workspace_dockerfile:
            raise RuntimeError("default workspace service omitted its catalog Dockerfile")
        if main_checkout.resolve() not in workspace_dockerfile.parents:
            raise RuntimeError("generated workspace Dockerfile escaped the private Reference checkout")
        if not all(receipts["default_container_startup"]["workspace_toolchain_markers"].values()):
            raise RuntimeError("generated default workspace image is missing its Rust/Bun toolchain")
        if not receipts["default_container_startup"]["workspace_rust_bun_mapping"]:
            raise RuntimeError("bundle default no longer maps the workspace service to workspace-rust-bun")
        if not receipts["default_container_startup"]["minio_image_in_compose"]:
            raise RuntimeError("default stack omitted the scoped source-built MinIO image override")
        print("PASS private Reference default container build/startup; workspace image retained and only MinIO uses the exact-source local fixture image", flush=True)
        default_down = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "down", "--json", timeout=600)
        default_started = False
        after_default_down = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "status", "--json", timeout=120)
        remaining_up = [item["name"] for item in after_default_down.get("services", []) if item.get("status") == "Up"]
        if remaining_up:
            raise RuntimeError(f"default container down left services active: {remaining_up}")
        default_scope_stopped = True
        receipts["default_container_down"] = {"down": default_down, "services_up_after": remaining_up}

        phase = "private MinIO catalog and scope evidence"
        success_receipts = fixture_root / "qualification-receipts.json"
        success_receipts.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
        success_receipts.chmod(0o600)
        print(f"QUALIFICATION RECEIPTS: {fixture_root / 'qualification-receipts.json'}", flush=True)
        return 0
    except Exception as error:
        traceback.print_exc(limit=8)
        detail = str(error).replace("qualification-local-only", "[REDACTED]").replace("minioadmin", "[REDACTED]")
        receipts["failure"] = {
            "phase": locals().get("phase", "unknown"),
            "error_type": type(error).__name__,
            "detail": detail[:1200],
        }
        failure_captures = []
        for checkout in started:
            try:
                names = [row["name"] for row in declared_host_processes(checkout)]
                if names:
                    failure_captures.append(
                        capture_runtime_evidence(
                            checkout, names, fixture_root,
                            "failure-before-owned-resource-cleanup",
                        )
                    )
            except Exception as capture_error:
                failure_captures.append({
                    "checkout": str(checkout),
                    "capture_error_type": type(capture_error).__name__,
                })
        receipts["failure_runtime_captures"] = failure_captures
        raise RuntimeError(f"Reference qualification failed during {locals().get('phase', 'unknown')}: {type(error).__name__}") from None
    finally:
        cleanup_ok = True
        empty_host_scopes_verified: set[Path] = set()
        if receipts.get("owner_uncertainty") is True:
            cleanup_ok = False
            receipts["cleanup"].append({
                "profile_purge_held": "a managed child failure had no retained owner state; the private runtime remains preserved",
            })
        if default_started:
            try:
                down = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "down", "--json", timeout=600)
                receipts["cleanup"].append({"default_container_down_after_failure": down})
                status = effigy_json(EFFIGY, main_checkout, runtime_env, "container", "status", "--json", timeout=120)
                remaining_up = [item["name"] for item in status.get("services", []) if item.get("status") == "Up"]
                receipts["cleanup"].append({"default_container_services_after_down": remaining_up})
                if remaining_up:
                    raise RuntimeError(f"default container stack remained up after cleanup: {remaining_up}")
                default_scope_stopped = True
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"default_container_down_error": type(error).__name__})
        retirable_scopes: set[Path] = set()
        for checkout in reversed(started):
            if checkout in hybrid_scopes_retired:
                receipts["cleanup"].append({
                    "checkout": str(checkout),
                    "hybrid_scope": "already stopped, reconciled, and retired while the private profile was available",
                })
                continue
            try:
                if checkout in hybrid_down_verified:
                    receipts["cleanup"].append({
                        "checkout": str(checkout),
                        "down": "not repeated; this exact hybrid scope was already down and verified before container-only assembly",
                    })
                else:
                    down = effigy_json(EFFIGY, checkout, runtime_env, "container", "hybrid", "down", "--json", timeout=300)
                    receipts["cleanup"].append({"checkout": str(checkout), "down": down})
                known_states = states_by_checkout.get(checkout)
                if known_states is not None and set(known_states) != {"api", "front", "admin"}:
                    cleanup_ok = False
                    receipts["cleanup"].append({"checkout": str(checkout),
                                                "state_verification": "incomplete-or-unknown-owner"})
                    continue
                if known_states is not None:
                    stopped = verify_stopped_scope(checkout, known_states, gateway_root)
                    receipts["cleanup"].append({"checkout": str(checkout), "stopped": stopped})
                declarations = declared_host_processes(checkout)
                if declarations:
                    empty_scope = verify_failed_scope_reconciled(checkout, gateway_root, runtime_env)
                    receipts["cleanup"].append({"checkout": str(checkout),
                                                "declared_host_scope_reconciled": empty_scope})
                else:
                    empty_scope = verify_no_host_children_started(checkout, runtime_env)
                    receipts["cleanup"].append({"checkout": str(checkout),
                                                "no_host_children_started": empty_scope})
                empty_host_scopes_verified.add(checkout)
                if checkout not in uncertain_checkouts:
                    retirable_scopes.add(checkout)
                else:
                    cleanup_ok = False
                    receipts["cleanup"].append({"checkout": str(checkout),
                                                "retire_held": "this scope recorded an uncertain owner; resource records are preserved"})
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"checkout": str(checkout), "down_or_verify_error": type(error).__name__})
        for checkout in reversed(started):
            if checkout not in retirable_scopes:
                receipts["cleanup"].append({"checkout": str(checkout),
                                            "retire_skipped": "owned-resource verification did not establish this exact scope as clear"})
                continue
            try:
                retired = effigy_json(EFFIGY, checkout, runtime_env, "container", "retire", "--yes", "--json", timeout=300)
                receipts["cleanup"].append({"checkout": str(checkout), "retire": retired})
                empty_scope_retired = (
                    checkout in empty_host_scopes_verified
                    and retired.get("idempotent") is True
                    and retired.get("scope") is None
                    and not retired.get("removed")
                )
                if ((retired.get("record_removed") is not True and not empty_scope_retired)
                        or retired.get("unverified_profiles")):
                    cleanup_ok = False
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"checkout": str(checkout), "retire_error": type(error).__name__})
        if default_scope_started and default_scope_stopped:
            try:
                retired = effigy_json(EFFIGY, main_checkout, runtime_env,
                                      "container", "retire", "--yes", "--json", timeout=300)
                receipts["cleanup"].append({"checkout": str(main_checkout), "default_scope_retire": retired})
                empty_verified_default = (
                    retired.get("idempotent") is True
                    and retired.get("scope") is None
                    and not retired.get("removed")
                    and not retired.get("remaining")
                    and not retired.get("unverified_profiles")
                )
                if ((retired.get("record_removed") is not True and not empty_verified_default)
                        or retired.get("unverified_profiles")):
                    cleanup_ok = False
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"checkout": str(main_checkout),
                                            "default_scope_retire_error": type(error).__name__})
        if profile_started:
            try:
                inventory_result = json.loads(run(
                    [EFFIGY, "container", "status", "--global", "--json"],
                    env=runtime_env, timeout=120, print_output=False,
                ).stdout)
                inventory = inventory_result.get("result") or {}
                count = inventory.get("environment_count")
                receipts["cleanup"].append({"global_runtime_after_scope_retirement": {
                    "ok": inventory_result.get("ok") is True,
                    "environment_count": count,
                }})
                if inventory_result.get("ok") is not True or count != 0:
                    cleanup_ok = False
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"global_runtime_inventory_error": type(error).__name__})
        gateway_can_down = True
        if gateway_attempted:
            try:
                current_gateway = gateway_json(EFFIGY, runtime_env, gateway_root, "status")
                remaining_routes = [route.get("domain") for route in current_gateway.get("routes", [])]
                receipts["cleanup"].append({"private_gateway_routes_before_down": remaining_routes})
                if remaining_routes:
                    cleanup_ok = False
                    gateway_can_down = False
            except Exception as error:
                cleanup_ok = False
                gateway_can_down = False
                receipts["cleanup"].append({"private_gateway_routes_error": type(error).__name__})
        if gateway_ready or gateway_attempted:
            try:
                if not gateway_ready:
                    status = gateway_json(EFFIGY, runtime_env, gateway_root, "status")
                    if status.get("private") is not True:
                        raise RuntimeError("private gateway status did not match this fixture root")
                    gateway_ready = status.get("running") is True
                if not gateway_can_down:
                    receipts["cleanup"].append({"gateway_down_held": "private gateway routes remain or could not be inspected"})
                else:
                    down = gateway_json(EFFIGY, runtime_env, gateway_root, "down") if gateway_ready else {"running": False}
                    receipts["cleanup"].append({"gateway_down": down})
                    if down.get("running") is True:
                        cleanup_ok = False
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"gateway_down_error": type(error).__name__})
        if profile_started and cleanup_ok:
            try:
                purged = run([EFFIGY, "container", "profile", "purge", "--profile", "effigy", "--yes", "--json"],
                             env=runtime_env, timeout=300, print_output=False)
                profile_status = run([EFFIGY, "container", "profile", "status", "--profile", "effigy", "--json"],
                                     env=runtime_env, timeout=120, print_output=False)
                status_result = json.loads(profile_status.stdout).get("result") or {}
                receipts["cleanup"].append({"private_profile_purge_exit": purged.returncode,
                                            "profile_status": status_result})
                if status_result.get("exists") is not False:
                    cleanup_ok = False
            except Exception as error:
                cleanup_ok = False
                receipts["cleanup"].append({"profile_purge_error": type(error).__name__})
        elif profile_started:
            print("HELD: private Colima profile was not purged because owned checkout retirement did not fully verify", flush=True)
        receipts["cleanup_verified"] = cleanup_ok
        receipts["last_phase"] = locals().get("phase", "unknown")
        receipt_path = fixture_root / "qualification-receipts.json"
        receipt_path.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        print(f"PRIVATE FIXTURE AND REDACTED RECEIPTS RETAINED: {fixture_root}", flush=True)
        if not cleanup_ok:
            raise RuntimeError("private fixture cleanup could not be fully verified; runtime profile remains held")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        print(f"REFERENCE RUNTIME QUALIFICATION BLOCKED: {error}", flush=True)
        raise SystemExit(1)
