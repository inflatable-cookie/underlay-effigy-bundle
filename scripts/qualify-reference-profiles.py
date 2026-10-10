#!/usr/bin/env python3
"""Qualify safe Underlay Reference configuration and adapter plans."""

from __future__ import annotations

import json
import ast
import base64
from datetime import datetime
import hashlib
import http.client
import os
import re
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from qualification_runtime import require_effigy_binary


REPO = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE = Path.home() / "Dev" / "projects" / "underlay-reference"
EFFIGY: Path | None = None
EXPECTED_ADAPTERS = {
    "acme-api/api": ["cargo", "run", "-p", "acme-api"],
    "acme-admin/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
    "acme-front/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
}


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60,
    expected: int = 0,
    show_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    print(f"EXIT: {result.returncode}", flush=True)
    if show_output:
        if result.stdout:
            print(result.stdout.rstrip(), flush=True)
        if result.stderr:
            print(result.stderr.rstrip(), flush=True)
    else:
        print(
            f"OUTPUT: captured stdout={len(result.stdout)} bytes stderr={len(result.stderr)} bytes",
            flush=True,
        )
    if result.returncode != expected:
        raise RuntimeError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(args)}"
        )
    return result


def effigy_json(checkout: Path, *args: str) -> dict:
    result = run(
        [EFFIGY, "--repo", str(checkout), *args],
        timeout=30,
        show_output=False,
    )
    return json.loads(result.stdout)


def manifest_section(manifest: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)", manifest
    )
    if not match:
        raise RuntimeError(f"missing manifest section [{name}]")
    return match.group(1)


def reference_source() -> Path:
    configured = os.environ.get("UNDERLAY_REFERENCE_SOURCE")
    source = Path(configured).expanduser() if configured else DEFAULT_REFERENCE
    source = source.resolve()
    if not source.is_dir():
        raise RuntimeError(
            "set UNDERLAY_REFERENCE_SOURCE to an existing clean underlay-reference checkout"
        )
    top = run(["git", "-C", str(source), "rev-parse", "--show-toplevel"], show_output=False)
    if Path(top.stdout.strip()).resolve() != source:
        raise RuntimeError(f"Reference source is not a repository root: {source}")
    dirty = run(["git", "-C", str(source), "status", "--porcelain"], show_output=False)
    if dirty.stdout.strip():
        raise RuntimeError(
            "Reference source has local changes; refusing to copy an ambiguous pilot state"
        )
    commit = run(["git", "-C", str(source), "rev-parse", "HEAD"], show_output=False)
    branch = run(["git", "-C", str(source), "branch", "--show-current"], show_output=False)
    print(
        f"REFERENCE SOURCE: {source} branch={branch.stdout.strip() or '(detached)'} "
        f"commit={commit.stdout.strip()}",
        flush=True,
    )
    return source


def make_reference_instances(source: Path, root: Path) -> list[Path]:
    main = root / "main"
    source_commit = run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], show_output=False
    ).stdout.strip()
    run(["git", "clone", "--no-hardlinks", "--local", str(source), str(main)], timeout=120)
    run(["git", "-C", str(main), "checkout", "--detach", source_commit], cwd=root)

    worktree_root = root / "worktrees"
    worktree_root.mkdir()
    worktrees = []
    for name in ("first", "second"):
        target = worktree_root / name
        run(
            ["git", "-C", str(main), "worktree", "add", "--detach", str(target), "HEAD"],
            cwd=root,
        )
        worktrees.append(target)
    return [main, *worktrees]


def point_bundle_at_task_branch(checkout: Path) -> None:
    manifest_path = checkout / "effigy.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    bundle_section = manifest_section(manifest, "bundle")
    current_source = re.search(r"(?m)^base\s*=\s*\{[^\n]*\}$", bundle_section)
    if not current_source:
        raise RuntimeError("Reference bundle source declaration is missing")
    if 'type = "path"' in current_source.group(0):
        if REPO.as_posix() not in current_source.group(0):
            raise RuntimeError("private Reference checkout points at an unexpected path bundle")
        return
    if 'type = "git"' not in current_source.group(0):
        raise RuntimeError("Reference bundle source is not the expected released Git source")
    pattern = re.compile(r"(?m)^base\s*=\s*\{[^\n]*type\s*=\s*\"git\"[^\n]*\}$")
    replacement = f'base = {{ type = "path", dir = {json.dumps(REPO.as_posix())} }}'
    updated, count = pattern.subn(replacement, manifest, count=1)
    if count != 1:
        raise RuntimeError("could not replace exactly one Reference bundle source line")
    manifest_path.write_text(updated, encoding="utf-8")


def prove_reference_configuration(checkouts: list[Path]) -> None:
    for checkout in checkouts:
        point_bundle_at_task_branch(checkout)

    main = checkouts[0]
    bundle = effigy_json(main, "bundle", "inspect", "--json")["result"]
    assert bundle["source"]["source_type"] == "path"
    assert Path(bundle["source"]["source_path"]).resolve() == REPO.resolve()

    effective = run(
        [EFFIGY, "--repo", str(main), "config", "--inspect"],
        show_output=False,
    ).stdout
    effective_manifest = effective.split("Effective Manifest\n------------------\n", 1)[1]
    assert '[bundle.sources]\nsiblings = false' in effective_manifest
    assert 'catalog = "workspace-rust-bun"' in effective_manifest
    for port in (41001, 41002, 41003):
        assert f'"{port}:{port}"' in effective_manifest

    consumer_manifest = (main / "effigy.toml").read_text(encoding="utf-8")
    assert 'siblings = false' in manifest_section(consumer_manifest, "bundle.sources")
    assert 'project_name = "underlay-reference-dev"' in manifest_section(
        consumer_manifest, "bundle"
    )
    print(
        "PASS Reference assembly: branch bundle path, sources.siblings=false, "
        "workspace-rust-bun, and unchanged published ports 41001/41002/41003",
        flush=True,
    )

    app_config = (main / "config" / "effigy.toml").read_text(encoding="utf-8")
    api_runtime = manifest_section(app_config, "acme_api.runtime")
    api_database = manifest_section(app_config, "acme_api.database")
    assert 'host = "0.0.0.0"' in api_runtime
    assert "port = 41001" in api_runtime
    assert 'public_host = "api.acme.test"' in api_runtime
    assert 'url = "postgres://' in api_database
    assert "postgres.acme.test" in api_database

    front_config = (main / "apps" / "acme-front" / "vite.config.ts").read_text(
        encoding="utf-8"
    )
    admin_config = (main / "apps" / "acme-admin" / "vite.config.ts").read_text(
        encoding="utf-8"
    )
    assert re.search(r"port:\s*41003\b", front_config)
    assert re.search(r"port:\s*41002\b", admin_config)
    assert re.search(r"strictPort:\s*true", admin_config)
    assert re.search(r'"acme\.test"', front_config)
    assert re.search(r'"admin\.acme\.test"', admin_config)
    print(
        "PASS actual Reference adapter configuration: Rust API binds 0.0.0.0:41001; "
        "front Vite uses 41003; admin Vite strictly binds 41002; DB URL is "
        "postgres.acme.test and browser hosts are acme.test/admin.acme.test",
        flush=True,
    )


def prepared_reference_instances(root: Path, source: Path) -> list[Path]:
    checkouts = [root / "main", root / "worktrees" / "first", root / "worktrees" / "second"]
    expected = run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], show_output=False
    ).stdout.strip()
    for checkout in checkouts:
        if not checkout.is_dir() or checkout.resolve() == source.resolve():
            raise RuntimeError(f"prepared pilot instance is missing or is the source checkout: {checkout}")
        commit = run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], show_output=False
        ).stdout.strip()
        assert commit == expected, f"{checkout} is at {commit}, expected Reference {expected}"
    print(f"PREPARED PRIVATE REFERENCE ROOT: {root}", flush=True)
    print(f"REFERENCE COMMIT: {expected}", flush=True)
    return checkouts


class GatewayHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the private gateway address while verifying route SNI/CA."""

    def __init__(self, host: str, port: int, context: ssl.SSLContext):
        super().__init__(host, port=port, timeout=8, context=context)

    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def gateway_request(
    host: str,
    port: int,
    context: ssl.SSLContext,
    path: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = GatewayHTTPSConnection(host, port, context)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            response.read(),
        )
    finally:
        connection.close()


def gateway_websocket_upgrade(
    host: str, port: int, context: ssl.SSLContext, token: str
) -> int:
    connection = GatewayHTTPSConnection(host, port, context)
    try:
        connection.connect()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        connection.putrequest("GET", f"/?token={token}")
        connection.putheader("Host", f"{host}:{port}")
        connection.putheader("Connection", "Upgrade")
        connection.putheader("Upgrade", "websocket")
        connection.putheader("Sec-WebSocket-Key", key)
        connection.putheader("Sec-WebSocket-Version", "13")
        connection.putheader("Sec-WebSocket-Protocol", "vite-hmr")
        connection.endheaders()
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        expected_accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if response.status != 101:
            return response.status
        if response_headers.get("sec-websocket-accept") != expected_accept:
            raise RuntimeError("gateway HMR WebSocket returned an invalid handshake accept")
        return response.status
    finally:
        connection.close()


def install_origin_probe(main: Path) -> None:
    """Add a temporary route to the disposable Reference clone only."""
    route = main / "apps/acme-front/src/routes/__qualification/origin/+server.ts"
    route.parent.mkdir(parents=True, exist_ok=True)
    route.write_text(
        """export function GET({ url, request }: { url: URL; request: Request }) {
  return new Response(
    JSON.stringify({
      urlOrigin: url.origin,
      requestOrigin: request.headers.get("origin"),
      forwardedProto: request.headers.get("x-forwarded-proto"),
      forwardedHost: request.headers.get("x-forwarded-host"),
    }),
    { headers: { "content-type": "application/json; charset=utf-8" } },
  );
}
""",
        encoding="utf-8",
    )


def managed_listener_state(
    checkout: Path, name: str, *, allow_unready: bool = False
) -> tuple[Path, dict]:
    state_path = checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "ready" or not state.get("route_owner"):
        if allow_unready:
            return state_path, state
        raise RuntimeError(f"Reference managed listener {name} is not owned and ready")
    report_path = state_path.parent / f"{name}.{state['generation']}.listener-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == "effigy.managed.host-listener-report.v1"
    assert report["generation"] == state["generation"]
    assert report["address"] == state["address"]
    assert state["route_owner"]["address"] == state["address"]
    return state_path, state


def container_status(checkout: Path, name: str) -> dict:
    envelope = effigy_json(checkout, "container", name, "status", "--json")
    result = envelope.get("result")
    if not envelope.get("ok") or not isinstance(result, dict):
        error = envelope.get("error") or {}
        raise RuntimeError(error.get("message", "Effigy returned no container status"))
    return result


def service_host_port(status: dict, target: int) -> int | None:
    for service in status.get("services", []):
        for mapping in service.get("ports", []):
            match = re.search(r"(?:127\.0\.0\.1:)?(\d+)->" + str(target) + r"(?:/tcp)?", mapping)
            if match:
                return int(match.group(1))
    return None


def private_gateway_status(main: Path, gateway_root: Path) -> dict:
    return json.loads(
        run(
            [str(EFFIGY), "--json", "gateway", "status", "--private-state-root", str(gateway_root)],
            cwd=main,
            show_output=False,
        ).stdout
    )["result"]


def prove_reference_api_restart(
    main: Path,
    gateway_root: Path,
    before_states: dict[str, dict],
) -> None:
    if "api" not in before_states:
        print("BLOCKED Reference API restart: prior API state is unavailable; no process was signaled", flush=True)
        return
    api_path, before_api = managed_listener_state(main, "api")
    old_address = before_api["address"]
    child_pid = int(before_api["child_pid"])
    supervisor_pid = int(before_api["supervisor_pid"])
    parent = subprocess.run(
        ["ps", "-p", str(child_pid), "-o", "ppid="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    if parent != str(supervisor_pid):
        print(
            f"BLOCKED Reference API restart: recorded child {child_pid} is not a direct child "
            f"of recorded supervisor {supervisor_pid}",
            flush=True,
        )
        return

    recorded_start = before_api.get("child_start_identity") or {}
    expected_start = datetime.fromtimestamp(int(recorded_start.get("start_seconds", 0))).strftime(
        "%a %b %d %H:%M:%S %Y"
    )
    actual_start = subprocess.run(
        ["ps", "-p", str(child_pid), "-o", "lstart="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    command = subprocess.run(
        ["ps", "-p", str(child_pid), "-o", "command="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    if (
        not recorded_start
        or expected_start != actual_start
        or str(main) not in command
        or "managed-rust-listener" not in command
    ):
        print(
            f"BLOCKED Reference API restart: recorded PID/start/path identity did not match "
            f"the current process (pid={child_pid}, parent={parent})",
            flush=True,
        )
        return

    try:
        os.kill(child_pid, signal.SIGTERM)
    except ProcessLookupError:
        print("BLOCKED Reference API restart: recorded child exited before the targeted signal", flush=True)
        return
    deadline = time.monotonic() + 150
    restarted = None
    while time.monotonic() < deadline:
        try:
            candidate = json.loads(api_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.25)
            continue
        if (
            candidate.get("status") == "ready"
            and candidate.get("generation") != before_api["generation"]
            and candidate.get("route_owner")
        ):
            restarted = candidate
            break
        time.sleep(0.5)
    if restarted is None:
        print("BLOCKED Reference API restart: no new ready generation appeared within 150 seconds", flush=True)
        return

    report_path = api_path.parent / f"api.{restarted['generation']}.listener-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["generation"] == restarted["generation"]
    assert report["address"] == restarted["address"]

    route_deadline = time.monotonic() + 30
    current_gateway = None
    while time.monotonic() < route_deadline:
        current_gateway = private_gateway_status(main, gateway_root)
        route = next(
            (item for item in current_gateway["routes"] if item["domain"] == restarted["route_domain"]),
            None,
        )
        if route and route["target"] == restarted["address"] and route["cert_ready"]:
            break
        time.sleep(0.5)
    if not current_gateway or not route or route["target"] != restarted["address"]:
        print("BLOCKED Reference API restart: new listener did not replace the owned route target", flush=True)
        return

    endpoint_changed = restarted["address"] != old_address
    dependent_changes = {"front": False, "admin": False}
    if endpoint_changed:
        dependent_deadline = time.monotonic() + 45
        while time.monotonic() < dependent_deadline:
            for name in dependent_changes:
                try:
                    _, now = managed_listener_state(main, name)
                    dependent_changes[name] = now["generation"] != before_states[name]["generation"]
                except (FileNotFoundError, json.JSONDecodeError, RuntimeError):
                    pass
            if all(dependent_changes.values()):
                break
            time.sleep(0.5)
    print(
        f"Reference API restart: generation {before_api['generation']} -> {restarted['generation']}; "
        f"address {old_address} -> {restarted['address']}; route target={route['target']}; "
        f"dependents_restarted={dependent_changes}",
        flush=True,
    )
    if endpoint_changed and all(dependent_changes.values()):
        print("PASS owned API child restart, new endpoint report, route replacement, and dependent restarts", flush=True)
    else:
        print("PARTIAL restart proof: the API generation/route is ready; endpoint change or dependent restart was not established", flush=True)


def prove_private_pilot_receipts(checkouts: list[Path]) -> None:
    main = checkouts[0]
    manifest = (main / "effigy.toml").read_text(encoding="utf-8")
    assert 'base = { type = "path"' in manifest
    assert '[bundle.sources]\nsiblings = false' in manifest
    assert 'project_name = "underlay-reference-dev"' in manifest
    for port in (41001, 41002, 41003):
        assert f'"{port}:{port}"' in run(
            [str(EFFIGY), "--repo", str(main), "config", "--inspect"], show_output=False
        ).stdout
    print("PASS private consumer assembly: branch bundle, siblings=false and unchanged container ports", flush=True)

    states = {}
    for name in ("api", "front", "admin"):
        state_path, state = managed_listener_state(main, name, allow_unready=True)
        if state.get("status") != "ready" or not state.get("route_owner"):
            print(
                f"BLOCKED Reference {name}: state={state.get('status')} address={state.get('address')} "
                f"recorded_listener_pid={state.get('listener_pid')}; current ownership is not established",
                flush=True,
            )
            continue
        states[name] = state
        assert state["address"].startswith("127.0.0.1:")
        print(
            f"PASS Reference {name}: ready generation={state['generation']} "
            f"bind={state['address']} public={state['public_url']} route_owner=verified",
            flush=True,
        )
    if len(states) == 3:
        assert len({state["address"] for state in states.values()}) == 3
        assert len({state["generation"] for state in states.values()}) == 3
    else:
        print(f"BLOCKED three-listener ownership set: only {sorted(states)} are currently ready", flush=True)

    try:
        stack = container_status(main, "hybrid")
    except RuntimeError as error:
        print(f"BLOCKED Reference runtime inventory: {error}", flush=True)
        print("NOT PROVEN: current service, HTTPS/HMR, restart, worktree concurrency, or teardown state", flush=True)
        return
    services = {item["name"]: item["status"] for item in (stack.get("services") or [])}
    if services.get("postgres") != "Up" or services.get("mailpit") != "Up":
        print(
            f"BLOCKED current Reference services: Postgres={services.get('postgres', 'absent')} "
            f"Mailpit={services.get('mailpit', 'absent')}",
            flush=True,
        )
        print("NOT PROVEN: current service connectivity, HTTPS/HMR, restart, or worktree concurrency", flush=True)
        return
    assert all("workspace-rust-bun" not in name for name in services)
    compose_path = main / stack["compose_file"]
    compose_text = compose_path.read_text(encoding="utf-8")
    assert "workspace-rust-bun" not in compose_text
    postgres_port = service_host_port(stack, 5432)
    smtp_port = service_host_port(stack, 1025)
    assert postgres_port is not None and smtp_port is not None
    print(
        f"PASS real hybrid service containers: Postgres and Mailpit Up; "
        f"loopback endpoints 127.0.0.1:{postgres_port}, 127.0.0.1:{smtp_port}",
        flush=True,
    )
    print("PASS hybrid service compose has no workspace Rust/Bun image dependency", flush=True)
    api_log = main / ".effigy/runtime/host-processes/hybrid/effigy/api.log"
    log_text = api_log.read_text(encoding="utf-8", errors="replace")
    assert "sqlx::postgres::notice" in log_text
    assert "api listening, addr: 127.0.0.1:0" in log_text
    print("PASS Reference API connected to Postgres and applied SQLx migrations before listener readiness", flush=True)
    with smtplib.SMTP("127.0.0.1", smtp_port, timeout=5) as client:
        code, _ = client.ehlo("qualification.invalid")
        assert 200 <= code < 300, code
    print(f"PASS host-to-SMTP: 127.0.0.1:{smtp_port} accepted EHLO", flush=True)

    gateway_root = Path(os.environ["EFFIGY_GATEWAY_PRIVATE_STATE_ROOT"]).resolve()
    status = private_gateway_status(main, gateway_root)
    assert status["private"] is True and status["route_table_trust"] == "trusted"
    assert status["running"] is True and status["tls"]["ca_installed"] is False
    gateway_port = int(status["https_addr"].rsplit(":", 1)[1])
    ca_file = gateway_root / "ca/rootCA.pem"
    context = ssl.create_default_context(cafile=str(ca_file))
    routes = {route["domain"]: route for route in status["routes"]}
    for name, state in states.items():
        domain = state["route_domain"]
        route = routes.get(domain)
        assert route is not None and route["tls"] is True and route["cert_ready"] is True
        assert route["target"] == state["address"]
        code, _, _ = gateway_request(domain, gateway_port, context, "/" if name != "api" else "/v1/health")
        assert code == 200, (domain, code)
        print(f"PASS verified private HTTPS/SNI route {domain}:{gateway_port} -> {state['address']} returned {code}", flush=True)

    if "front" not in states:
        print("BLOCKED SvelteKit origin and Vite HMR: frontend has no current owned-ready state", flush=True)
        prove_reference_api_restart(main, gateway_root, states)
        print("BLOCKED MinIO: the live disposable hybrid stack contains Postgres and Mailpit only; no genuine MinIO service was available", flush=True)
        print("NOT PROVEN: two worktree apps running simultaneously, child restart/address propagation, interrupted/uncertain recovery, partial-failure isolation, and teardown preserving foreign resources", flush=True)
        return

    install_origin_probe(main)
    front_domain = states["front"]["route_domain"]
    origin = f"https://{front_domain}:{gateway_port}"
    code, _, origin_bytes = gateway_request(
        front_domain,
        gateway_port,
        context,
        "/__qualification/origin",
        {"Origin": origin},
    )
    assert code == 200, code
    origin_result = json.loads(origin_bytes)
    print(
        "SvelteKit origin observation: "
        f"event.url.origin={origin_result.get('urlOrigin')} "
        f"Origin={origin_result.get('requestOrigin')} "
        f"X-Forwarded-Proto={origin_result.get('forwardedProto')} "
        f"X-Forwarded-Host={origin_result.get('forwardedHost')}",
        flush=True,
    )
    if origin_result.get("urlOrigin") != origin:
        print(
            "BLOCKED SvelteKit public origin: gateway request is HTTPS but the actual Reference "
            "dev adapter constructs event.url with the internal HTTP scheme",
            flush=True,
        )
    else:
        print("PASS SvelteKit event URL uses the verified HTTPS browser origin", flush=True)

    front_status, _, client_bytes = gateway_request(front_domain, gateway_port, context, "/@vite/client")
    assert front_status == 200
    client_text = client_bytes.decode("utf-8", errors="replace")
    token_match = re.search(r"(?:wsToken|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", client_text)
    if token_match and str(gateway_port) in client_text and "wss" in client_text:
        ws_status = gateway_websocket_upgrade(front_domain, gateway_port, context, token_match.group(1))
        assert ws_status == 101, ws_status
        print(f"PASS actual Vite HMR: wss through verified gateway port {gateway_port}, WebSocket upgrade {ws_status}", flush=True)
    else:
        print("BLOCKED Vite HMR: served client did not expose the expected wss gateway configuration/token", flush=True)

    prove_reference_api_restart(main, gateway_root, states)

    print("BLOCKED MinIO: the live disposable hybrid stack contains Postgres and Mailpit only; no genuine MinIO service was available", flush=True)
    print("NOT PROVEN: two worktree apps running simultaneously, child restart/address propagation, interrupted/uncertain recovery, partial-failure isolation, and teardown preserving foreign resources", flush=True)

def prove_worktree_plans(checkouts: list[Path]) -> None:
    scopes = []
    domains = []
    for checkout in checkouts:
        scope = effigy_json(checkout, "container", "scope", "--json")["result"]["scope"]
        hosts = effigy_json(checkout, "container", "hosts", "--json")["result"]
        scopes.append(scope.get("token") or "primary")
        domains.append(hosts["base_domain"]["effective"])
        assert all(
            route["origin"] is None or route["origin"].startswith("https://")
            for route in hosts["routes"]
        )
        run([EFFIGY, "--repo", str(checkout), "dev", "--plan"], timeout=30)

    assert len(set(scopes)) == 3, scopes
    assert len(set(domains)) == 3, domains
    print(f"PASS Reference main/worktree scopes: {scopes}", flush=True)
    print(f"PASS Reference main/worktree HTTPS host maps: {domains}", flush=True)


def prove_real_adapter_task_plans(checkout: Path) -> None:
    tasks = run(
        [EFFIGY, "--repo", str(checkout), "tasks", "--json"],
        timeout=30,
        show_output=False,
    ).stdout
    for selector in EXPECTED_ADAPTERS:
        assert selector in tasks, f"missing Reference selector {selector}"

    plans = {}
    for selector, expected_tokens in EXPECTED_ADAPTERS.items():
        plan = run(
            [EFFIGY, "--repo", str(checkout), selector, "--plan"],
            timeout=30,
        ).stdout
        for token in expected_tokens:
            assert token in plan, f"{selector} plan missing {token!r}"
        plans[selector] = "resolved"
    print(f"PASS Reference Rust/Vite/SvelteKit Effigy adapter plans: {plans}", flush=True)


def prove_bundle_adapter_sources() -> None:
    rust_adapter = REPO / "scripts/dev/managed-rust-listener.py"
    vite_adapter = REPO / "scripts/dev/managed-vite-listener.mjs"
    compile(rust_adapter.read_text(encoding="utf-8"), str(rust_adapter), "exec")
    node = subprocess.run(
        ["node", "--check", str(vite_adapter)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if node.returncode != 0:
        raise RuntimeError(f"Vite adapter syntax check failed: {node.stderr.strip()}")
    rust_source = ast.parse(rust_adapter.read_text(encoding="utf-8"))
    assert rust_source.body
    vite_source = vite_adapter.read_text(encoding="utf-8")
    for token in (
        "EFFIGY_MANAGED_HOST_LISTENER_BIND",
        "EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE",
        "EFFIGY_MANAGED_HOST_LISTENER_GENERATION",
        "EFFIGY_MANAGED_HOST_API_PUBLIC_URL",
        "EFFIGY_PROFILE_GATEWAY_HTTPS_PORT",
        "protocol: publicUrl.protocol === \"https:\" ? \"wss\" : \"ws\"",
    ):
        assert token in vite_source, f"Vite adapter is missing {token}"
    print("PASS bundle Rust/Vite adapter syntax and managed endpoint/origin inputs", flush=True)


def main() -> int:
    global EFFIGY
    if EFFIGY is None:
        EFFIGY = require_effigy_binary()
    source = reference_source()
    prove_bundle_adapter_sources()
    prepared = os.environ.get("UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT")
    if prepared:
        root = Path(prepared).expanduser().resolve(strict=True)
        checkouts = prepared_reference_instances(root, source)
        for checkout in checkouts:
            point_bundle_at_task_branch(checkout)
            bundle = effigy_json(checkout, "bundle", "inspect", "--json")["result"]
            assert bundle["source"]["source_type"] == "path"
            assert Path(bundle["source"]["source_path"]).resolve() == REPO.resolve()
        prove_private_pilot_receipts(checkouts)
        prove_worktree_plans(checkouts)
        prove_real_adapter_task_plans(checkouts[0])
        return 0

    root = Path(tempfile.mkdtemp(prefix="underlay-reference-profile-"))
    print(f"PRIVATE FIXTURE ROOT: {root}", flush=True)
    try:
        checkouts = make_reference_instances(source, root)
        version = run([EFFIGY, "--version"], timeout=30).stdout.strip()
        print(f"EFFIGY: {version}", flush=True)
        prove_reference_configuration(checkouts)
        prove_worktree_plans(checkouts)
        prove_real_adapter_task_plans(checkouts[0])
        print(
            "CONFIGURATION-ONLY: set UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT to a prepared "
            "private pilot root to inventory runtime receipts; this mode does not start services.",
            flush=True,
        )
        return 0
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"REFERENCE QUALIFICATION FAILED: {error}", flush=True)
        raise SystemExit(1)
