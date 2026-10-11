#!/usr/bin/env python3
"""Qualify safe Underlay Reference configuration and adapter plans."""

from __future__ import annotations

import json
import ast
import base64
from datetime import datetime
import fcntl
import hashlib
import http.client
import os
import pty
import re
import secrets as py_secrets
import select
import shlex
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import termios
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from qualification_runtime import require_effigy_binary


REPO = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE = Path.home() / "Dev" / "projects" / "underlay-reference"
EFFIGY: str | None = None
LAST_API_RESTART_DIAGNOSTIC: dict = {}
EXPECTED_ADAPTERS = {
    "acme-api/api": ["cargo", "run", "-p", "acme-api"],
    "acme-admin/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
    "acme-front/dev": ["vite", "dev", "--host", "0.0.0.0", "--force"],
}


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 60,
    expected: int = 0,
    show_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
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
        context = ""
        if "--json" in args:
            try:
                envelope = json.loads(result.stdout)
                error = envelope.get("error") or {}
                message = error.get("message")
                code = error.get("code")
                if isinstance(message, str):
                    context = f"; Effigy error={message[:800]}"
                elif isinstance(code, str):
                    context = f"; Effigy error code={code}"
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        raise RuntimeError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(args)}{context}"
        )
    return result


def effigy_json(checkout: Path, *args: str, env: dict[str, str] | None = None) -> dict:
    result = run(
        [EFFIGY, "--repo", str(checkout), *args],
        env=env,
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
    if '[bundle.sources]\nsiblings = false' not in effective_manifest:
        raise RuntimeError("default Reference assembly did not preserve bundle.sources.siblings=false")
    if "[containers.hybrid_services]" in effective_manifest or '[tasks."dev:hybrid"]' in effective_manifest:
        raise RuntimeError("omitted profiles.enabled unexpectedly emitted opt-in profile declarations")
    bundle_inputs = (REPO / "bundle.toml").read_text(encoding="utf-8")
    export_template = (REPO / "export.toml").read_text(encoding="utf-8")
    if not re.search(r'(?m)^name = "profiles\.enabled"\ntype = "bool"\n[^\n]*\ndefault = false$', bundle_inputs):
        raise RuntimeError("profiles.enabled must default to false in the bundle input schema")
    if '[manifest]\nminimum_effigy_version = "{% if inputs.profiles.enabled %}0.14.1{% else %}0.13.1{% endif %}"' not in export_template:
        raise RuntimeError("profile input must raise the manifest floor only to 0.14.1; defaults remain 0.13.1")
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


def safe_secret_terminal_error(raw_output: bytes, passphrase: bytes) -> str:
    text = raw_output.decode("utf-8", errors="replace")
    text = text.replace(passphrase.decode("ascii"), "[REDACTED]")
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)", r"\1[REDACTED]\2", text)
    text = re.sub(
        r"(?i)(password|secret|token|authorization)(\s*[:=]\s*)[^,;\s]+",
        r"\1\2[REDACTED]",
        text,
    )
    json_start = text.find("{")
    if json_start >= 0:
        try:
            envelope, _ = json.JSONDecoder().raw_decode(text[json_start:])
            error = envelope.get("error") if isinstance(envelope, dict) else None
            message = error.get("message") if isinstance(error, dict) else None
            if isinstance(message, str):
                return message[:800]
        except json.JSONDecodeError:
            pass
    lines = [line.strip() for line in text.splitlines()
             if re.search(r"(?i)error|failed|invalid|missing|requires|not found", line)]
    return " | ".join(lines)[-800:]


def run_secret_prompt(checkout: Path, env: dict[str, str], action: str,
                      passphrase: bytes) -> None:
    """Use Effigy's normal interactive secret command without logging input."""
    command = [EFFIGY, "--repo", str(checkout), "secrets", action, "--json"]
    print(f"COMMAND: {EFFIGY} --repo {checkout} secrets {action} --json [passphrase via private TTY]", flush=True)
    master_fd, slave_fd = pty.openpty()
    attributes = termios.tcgetattr(slave_fd)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave_fd, termios.TCSANOW, attributes)

    def acquire_controlling_tty() -> None:
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        command,
        cwd=checkout,
        env=env,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        preexec_fn=acquire_controlling_tty,
    )
    os.close(slave_fd)
    output_tail = bytearray()
    prompt_tail = bytearray()
    prompt = b"create vault passphrase:" if action == "init" else b"vault passphrase:"
    sent = False
    deadline = time.monotonic() + 120
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Effigy secrets {action} exceeded its private TTY timeout")
            ready, _, _ = select.select([master_fd], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(master_fd, 2048)
            except OSError:
                break
            if not chunk:
                break
            output_tail.extend(chunk)
            if len(output_tail) > 8192:
                del output_tail[:-8192]
            prompt_tail.extend(chunk.lower())
            if len(prompt_tail) > 256:
                del prompt_tail[:-256]
            if not sent and prompt in prompt_tail:
                os.write(master_fd, passphrase + b"\n")
                sent = True
        code = process.wait(timeout=max(1, int(deadline - time.monotonic())))
    except Exception:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        raise
    finally:
        os.close(master_fd)
    detail = safe_secret_terminal_error(bytes(output_tail), passphrase)
    if not sent:
        raise RuntimeError(f"Effigy secrets {action} did not request the expected passphrase prompt; {detail or 'no safe diagnostic emitted'}")
    print(f"EXIT: {code}; passphrase input and terminal output suppressed", flush=True)
    if code != 0:
        raise RuntimeError(f"Effigy secrets {action} exited {code}; {detail or 'no safe diagnostic emitted'}")


def initialize_reference_fixture_secrets(checkouts: list[Path], env: dict[str, str]) -> dict[str, object]:
    """Initialize separate declared local-dev vaults in all private identities."""
    initialized = []
    for checkout in checkouts:
        vault_path = checkout / ".effigy/secrets/local.vault"
        if vault_path.exists():
            raise RuntimeError("fresh private Reference identity unexpectedly already contains an Effigy vault")
        manifest_path = checkout / "effigy.toml"
        original_manifest = manifest_path.read_text(encoding="utf-8")
        fixture_manifest = original_manifest
        for name in ("auth_jwt_private_key", "auth_jwt_public_key"):
            header = f"[secrets.keys.{name}]"
            start = fixture_manifest.find(header)
            if start < 0:
                raise RuntimeError(f"private Reference fixture lacks the declared secret {name}")
            next_table = fixture_manifest.find("\n[", start + len(header))
            end = next_table if next_table >= 0 else len(fixture_manifest)
            section = fixture_manifest[start:end]
            changed, count = re.subn(r"(?m)^required\s*=\s*true\s*$",
                                     "required = false", section, count=1)
            if count != 1:
                raise RuntimeError(f"private Reference fixture secret {name} was not required before bootstrap")
            fixture_manifest = fixture_manifest[:start] + changed + fixture_manifest[end:]
        print("FIXTURE ONLY: temporarily mark the generated JWT keys optional for this identity's vault bootstrap; restore required declarations before doctor/runtime", flush=True)
        manifest_path.write_text(fixture_manifest, encoding="utf-8")
        passphrase = py_secrets.token_urlsafe(36).encode("ascii")
        try:
            run_secret_prompt(checkout, env, "init", passphrase)
        finally:
            manifest_path.write_text(original_manifest, encoding="utf-8")
        run_secret_prompt(checkout, env, "unlock", passphrase)
        mode = vault_path.stat().st_mode & 0o777
        if mode != 0o600:
            raise RuntimeError(f"private Reference Effigy vault permissions are {mode:o}, expected 600")
        initialized.append({"checkout": str(checkout), "vault_mode": "0600",
                            "passphrase_recorded": False, "secret_values_recorded": False})
    for checkout in checkouts:
        doctor = effigy_json(checkout, "secrets", "doctor", "--json")
        if not doctor.get("ok"):
            error = doctor.get("error") or {}
            message = error.get("message") if isinstance(error, dict) else None
            raise RuntimeError(f"private Reference secrets doctor did not pass: {str(message or 'unknown safe status')[:500]}")
    print("PASS three identity-local Effigy vaults initialized/unlocked; required declarations resolve for each private Reference checkout, values withheld", flush=True)
    return {
        "vaults": initialized,
        "required_jwt_declarations_restored_before_runtime": True,
        "secrets_doctor_passed_checkout_count": len(checkouts),
        "secret_values_or_passphrase_recorded": False,
    }


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


def install_public_origin_hooks(checkouts: list[Path]) -> None:
    """Opt the private front/admin fixtures into the bundle hook wrapper."""
    helper = (REPO / "scripts/dev/sveltekit-public-origin.mjs").resolve().as_uri()
    for checkout in checkouts:
        for app in ("acme-front", "acme-admin"):
            app_root = checkout / "apps" / app
            config_path = app_root / "svelte.config.js"
            config = config_path.read_text(encoding="utf-8")
            if "qualification-hooks.server.js" not in config:
                updated, count = re.subn(
                    r"(?m)(\bkit\s*:\s*\{)",
                    r'\1\n\t\tfiles: { hooks: { server: "src/qualification-hooks.server.js" } },',
                    config,
                    count=1,
                )
                if count != 1:
                    raise RuntimeError(f"could not opt {app} into the disposable SvelteKit hook")
                config_path.write_text(updated, encoding="utf-8")

            wrapper = app_root / "src/qualification-hooks.server.js"
            wrapper.write_text(
                f'''import * as existingHooks from "./hooks.server.js";
import {{ withSvelteKitPublicOrigin }} from {json.dumps(helper)};

export * from "./hooks.server.js";
const publicOriginHandle = withSvelteKitPublicOrigin(existingHooks.handle, {{
  enabled: import.meta.env.DEV && process.env.EFFIGY_PROFILE_PUBLIC_ORIGIN === "true",
  publicOrigin: process.env.EFFIGY_PROFILE_PUBLIC_URL,
  readinessPath: "/",
  readinessHost: process.env.EFFIGY_PROFILE_SELF_DECLARED,
}});
export const handle = async (input) => {{
  try {{
    return await publicOriginHandle(input);
  }} catch (error) {{
    const request = input?.event?.request;
    console.error("[qualification public-origin diagnostics]", JSON.stringify({{
      error: error instanceof Error ? error.message : "unknown hook error",
      publicOrigin: process.env.EFFIGY_PROFILE_PUBLIC_URL,
      requestOrigin: request ? new URL(request.url).origin : null,
      eventOrigin: input?.event?.url?.origin ?? null,
      host: request?.headers?.get("host") ?? null,
      forwardedHost: request?.headers?.get("x-forwarded-host") ?? null,
      forwardedProto: request?.headers?.get("x-forwarded-proto") ?? null,
    }}));
    throw error;
  }}
}};
''',
                encoding="utf-8",
            )


def install_origin_probe(main: Path) -> None:
    """Add temporary front/admin probes to the disposable Reference clone only."""
    for app in ("acme-front", "acme-admin"):
        readiness = main / "apps" / app / "src/routes/__effigy/ready/+server.ts"
        readiness.parent.mkdir(parents=True, exist_ok=True)
        readiness.write_text(
            'export function GET() { return new Response("ready", { status: 200 }); }\n',
            encoding="utf-8",
        )
        route = main / "apps" / app / "src/routes/__qualification/origin/+server.ts"
        route.parent.mkdir(parents=True, exist_ok=True)
        route.write_text(
            """export function GET({ url, request }: { url: URL; request: Request }) {
  return new Response(
    JSON.stringify({
      urlOrigin: url.origin,
      requestUrl: request.url,
      requestUrlOrigin: new URL(request.url).origin,
      requestPath: new URL(request.url).pathname,
      requestSearch: new URL(request.url).search,
      method: request.method,
      host: request.headers.get("host"),
      origin: request.headers.get("origin"),
      forwardedProto: request.headers.get("x-forwarded-proto"),
      forwardedHost: request.headers.get("x-forwarded-host"),
    }),
    { headers: { "content-type": "application/json; charset=utf-8" } },
  );
}
""",
            encoding="utf-8",
        )


def fixture_public_origin_observations(
    main: Path, states: dict[str, dict], gateway_port: int, context: ssl.SSLContext
) -> None:
    for app in ("acme-front", "acme-admin"):
        wrapper = main / "apps" / app / "src/qualification-hooks.server.js"
        if not wrapper.is_file():
            raise RuntimeError(
                f"{app} public-origin wrapper was not installed before app startup"
            )
    for name in ("front", "admin"):
        if name not in states:
            raise RuntimeError(f"cannot qualify {name} public origin without an owned ready route")
        domain = states[name]["route_domain"]
        origin = f"https://{domain}:{gateway_port}"
        path = "/__qualification/origin?probe=public-origin"
        code, _, body = gateway_request(
            domain,
            gateway_port,
            context,
            path,
            {"Host": f"{domain}:{gateway_port}", "Origin": origin},
        )
        assert code == 200, (name, code)
        result = json.loads(body)
        print(
            f"Reference {name} origin probe: status={code} path={result.get('requestPath')} "
            f"Host={result.get('host')} Origin={result.get('origin')} "
            f"X-Forwarded-Proto={result.get('forwardedProto')} "
        f"X-Forwarded-Host={result.get('forwardedHost')} "
        f"event.url.origin={result.get('urlOrigin')} "
            f"request.url.origin={result.get('requestUrlOrigin')}",
            flush=True,
        )
        expected = origin
        if (
            result.get("urlOrigin") != expected
            or result.get("requestUrlOrigin") != expected
            or result.get("requestPath") != "/__qualification/origin"
            or result.get("requestSearch") != "?probe=public-origin"
        ):
            raise RuntimeError(f"{name} SvelteKit public-origin probe did not preserve configured HTTPS URL")
    print("PASS actual Reference front/admin configured HTTPS origins through verified private gateway", flush=True)


def managed_listener_state(
    checkout: Path,
    name: str,
    *,
    allow_unready: bool = False,
    expected_route_domain: str | None = None,
) -> tuple[Path, dict]:
    candidates = (
        checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{name}.listener.json",
        checkout / ".effigy/runtime/host-processes/hybrid/effigy" / f"{name}.listener.json",
    )
    state_path = next((path for path in candidates if path.is_file()), candidates[0])
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
    route_domain = state.get("route_domain")
    if not isinstance(route_domain, str) or not route_domain:
        raise RuntimeError(f"Reference managed listener {name} has no effective route domain")
    if expected_route_domain is not None and route_domain != expected_route_domain:
        raise RuntimeError(
            f"Reference managed listener {name} route differs from the current effective route: "
            f"expected {expected_route_domain}, got {route_domain}"
        )
    public_url = state.get("public_url")
    parsed_public_url = urlsplit(public_url) if isinstance(public_url, str) else None
    if parsed_public_url is None or parsed_public_url.hostname != route_domain:
        raise RuntimeError(f"Reference managed listener {name} public URL does not use its effective route")
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
            match = re.fullmatch(r"127\.0\.0\.1:(\d+)->" + str(target) + r"(?:/tcp)?", mapping)
            if match:
                return int(match.group(1))
    return None


def process_ancestry_chain(process_pid: int, ancestor_pid: int, parents: dict[int, int]) -> list[int] | None:
    """Return the current PID chain to a known owner, failing closed on gaps or cycles."""
    chain = [process_pid]
    visited = {process_pid}
    current = process_pid
    while current != ancestor_pid:
        parent = parents.get(current)
        if parent is None or parent in visited:
            return None
        chain.append(parent)
        visited.add(parent)
        current = parent
    return chain


def process_parent_map() -> dict[int, int]:
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    parents: dict[int, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            process_pid, parent_pid = map(int, fields)
        except ValueError:
            continue
        parents[process_pid] = parent_pid
    return parents


def configured_reference_api_task_cwd(checkout: Path) -> dict[str, str]:
    """Resolve the exact Reference API task's configured catalog working directory."""
    root = checkout.resolve(strict=True)
    root_manifest_path = root / "effigy.toml"
    if not root_manifest_path.is_file():
        raise RuntimeError("Reference checkout has no root Effigy manifest")
    try:
        root_manifest = _read_contract_toml_tables(root_manifest_path)
    except (OSError, ValueError) as error:
        raise RuntimeError("Reference root Effigy manifest could not establish API catalog mapping") from error
    directories = root_manifest.get("bundle.dirs")
    catalogs = root_manifest.get("bundle.catalogs")
    relative = directories.get("api") if isinstance(directories, dict) else None
    alias = catalogs.get("api") if isinstance(catalogs, dict) else None
    if relative != "apps/acme-api" or alias != "acme-api":
        raise RuntimeError("Reference API bundle directory/catalog mapping is missing or ambiguous")

    catalog_root = (root / relative).resolve(strict=True)
    if catalog_root == root or not catalog_root.is_relative_to(root):
        raise RuntimeError("Reference API catalog resolves outside its canonical checkout")
    catalog_manifest_path = catalog_root / "effigy.toml"
    if not catalog_manifest_path.is_file():
        raise RuntimeError("Reference API catalog manifest is missing")
    try:
        catalog_manifest = _read_contract_toml_tables(catalog_manifest_path)
    except (OSError, ValueError) as error:
        raise RuntimeError("Reference API catalog manifest could not establish its task cwd") from error

    catalog = catalog_manifest.get("catalog")
    tasks = catalog_manifest.get("tasks")
    task_run = tasks.get("api") if isinstance(tasks, dict) else None
    if not isinstance(catalog, dict) or catalog.get("alias") != alias:
        raise RuntimeError("Reference API catalog alias does not match the assembled project mapping")
    if task_run != "cd {repo} && cargo run -p acme-api {args}":
        raise RuntimeError("Reference API task command no longer establishes its exact catalog cwd")
    return {
        "selector": f"{alias}/api",
        "checkout_root": str(root),
        "root_manifest": str(root_manifest_path),
        "catalog_relative": relative,
        "catalog_alias": alias,
        "catalog_manifest": str(catalog_manifest_path),
        "task": "api",
        "task_run": task_run,
        "expected_cwd": str(catalog_root),
    }


def canonical_process_cwd(paths: list[str]) -> dict[str, object]:
    """Require exactly one live, resolvable directory from a process cwd query."""
    result: dict[str, object] = {"observed_paths": list(paths), "canonical_path": None, "error": None}
    if len(paths) != 1:
        result["error"] = "cwd query returned no path or an ambiguous path set"
        return result
    try:
        candidate = Path(paths[0]).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        result["error"] = f"cwd path could not be canonicalized: {type(error).__name__}"
        return result
    if not candidate.is_dir():
        result["error"] = "cwd path is not a directory"
        return result
    result["canonical_path"] = str(candidate)
    return result


def process_cwd_matches(paths: list[str], expected: Path) -> tuple[bool, dict[str, object]]:
    observation = canonical_process_cwd(paths)
    try:
        canonical_expected = expected.resolve(strict=True)
    except (OSError, RuntimeError):
        return False, observation
    observation["expected_canonical_path"] = str(canonical_expected)
    return observation["canonical_path"] == str(canonical_expected), observation


def canonical_process_executable(paths: list[str]) -> dict[str, object]:
    """Require one live executable file path from the OS process inventory."""
    result: dict[str, object] = {"observed_paths": list(paths), "canonical_path": None,
                                 "sha256": None, "error": None}
    if len(paths) != 1:
        result["error"] = "executable query returned no path or an ambiguous path set"
        return result
    try:
        candidate = Path(paths[0]).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        result["error"] = f"executable path could not be canonicalized: {type(error).__name__}"
        return result
    if not candidate.is_file():
        result["error"] = "executable path is not a file"
        return result
    result["canonical_path"] = str(candidate)
    result["sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return result


def process_executable_matches(paths: list[str], expected: Path,
                               expected_sha256: str) -> tuple[bool, dict[str, object]]:
    observation: dict[str, object] = {
        "observed_paths": list(paths), "canonical_path": None, "sha256": None,
        "matching_path_count": 0, "error": None,
    }
    try:
        canonical_expected = expected.resolve(strict=True)
    except (OSError, RuntimeError):
        observation["error"] = "expected executable path could not be canonicalized"
        return False, observation
    if not canonical_expected.is_file():
        observation["error"] = "expected executable path is not a file"
        return False, observation
    matching_paths = []
    for raw_path in paths:
        try:
            candidate = Path(raw_path).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate == canonical_expected and candidate.is_file():
            matching_paths.append(candidate)
    observation["matching_path_count"] = len(matching_paths)
    if len(matching_paths) != 1:
        observation["error"] = "process executable mapping omitted or ambiguously repeated the expected binary"
        observation["expected_canonical_path"] = str(canonical_expected)
        observation["expected_sha256"] = expected_sha256
        return False, observation
    observed_sha256 = hashlib.sha256(canonical_expected.read_bytes()).hexdigest()
    observation["canonical_path"] = str(canonical_expected)
    observation["sha256"] = observed_sha256
    observation["expected_canonical_path"] = str(canonical_expected)
    observation["expected_sha256"] = expected_sha256
    return observed_sha256 == expected_sha256, observation


def _read_contract_toml_tables(path: Path) -> dict[str, dict[str, str]]:
    """Read only the simple quoted string tables used by Reference's task contract."""
    tables: dict[str, dict[str, str]] = {}
    current = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        table = re.fullmatch(r"\[([A-Za-z0-9_.-]+)\]", line)
        if table:
            current = table.group(1)
            tables.setdefault(current, {})
            continue
        if line.startswith("[["):
            current = None
            continue
        if current is None or not line or line.startswith("#"):
            continue
        entry = re.fullmatch(r"([A-Za-z0-9_-]+)\s*=\s*(\"(?:[^\"\\]|\\.)*\")", line)
        if entry:
            tables[current][entry.group(1)] = json.loads(entry.group(2))
    return tables


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
    *,
    expected_api_binary: dict[str, str] | None = None,
    diagnostic_sink=None,
    require_durable_preflight: bool = False,
) -> bool:
    global LAST_API_RESTART_DIAGNOSTIC
    LAST_API_RESTART_DIAGNOSTIC = {
        "status": "unproven",
        "phase": "preflight",
        "termination_signal": "SIGKILL",
    }

    def record_preflight(fields: dict) -> bool:
        global LAST_API_RESTART_DIAGNOSTIC
        receipt = {
            "status": "unproven",
            "phase": "preflight",
            "signal_sent": False,
            "termination_signal": "SIGKILL",
            **fields,
        }
        LAST_API_RESTART_DIAGNOSTIC = receipt
        if diagnostic_sink is None:
            if require_durable_preflight:
                receipt["reason"] = "durable restart preflight receipt is required but unavailable"
                return False
            return True
        try:
            diagnostic_sink("api_restart_preflight", **receipt)
        except BaseException as error:
            receipt["reason"] = "durable restart preflight receipt could not be written"
            receipt["receipt_error_type"] = type(error).__name__
            return False
        receipt["durable_pre_signal_receipt"] = "written"
        return True

    if "api" not in before_states:
        record_preflight({"reason": "prior API state is unavailable"})
        print("BLOCKED Reference API restart: prior API state is unavailable; no process was signaled", flush=True)
        return False
    try:
        api_path, before_api = managed_listener_state(main, "api")
    except BaseException as error:
        record_preflight({
            "reason": "current API owner state could not be established",
            "exception_type": type(error).__name__,
        })
        print("BLOCKED Reference API restart: current owner state is uncertain; no process was signaled", flush=True)
        return False
    old_address = before_api["address"]
    child_pid = int(before_api["child_pid"])
    supervisor_pid = int(before_api["supervisor_pid"])
    listener_pid = int(before_api["listener_pid"])
    ancestry_snapshot = process_parent_map()
    child_parent = ancestry_snapshot.get(child_pid)
    listener_parent = ancestry_snapshot.get(listener_pid)
    listener_ancestry = process_ancestry_chain(listener_pid, child_pid, ancestry_snapshot)
    if child_parent != supervisor_pid or listener_ancestry is None:
        record_preflight({
            "reason": "recorded supervisor/adapter/listener ancestry did not match",
            "child_pid": child_pid,
            "listener_pid": listener_pid,
            "recorded_supervisor_pid": supervisor_pid,
            "observed_child_parent_pid": child_parent,
            "observed_listener_parent_pid": listener_parent,
            "observed_listener_ancestry": listener_ancestry,
        })
        print(
            "BLOCKED Reference API restart before signal: recorded supervisor/adapter/listener "
            f"ancestry did not match (supervisor={supervisor_pid}, adapter={child_pid}, "
            f"listener={listener_pid}, observed_parents={child_parent}/{listener_parent}, "
            f"listener_chain={listener_ancestry})",
            flush=True,
        )
        return False

    try:
        cwd_contract = configured_reference_api_task_cwd(main)
    except BaseException as error:
        record_preflight({
            "reason": "configured Reference API task cwd could not be established",
            "exception_type": type(error).__name__,
            "configuration_error": str(error)[:500],
            "checkout_root": str(main.resolve(strict=False)),
            "selector_provenance": "root bundle mapping -> acme-api catalog -> api task",
        })
        print("BLOCKED Reference API restart before signal: configured API task cwd is unknown or ambiguous", flush=True)
        return False

    recorded_start = before_api.get("listener_start_identity") or {}
    try:
        expected_start = datetime.fromtimestamp(int(recorded_start.get("start_seconds", 0))).strftime(
            "%a %b %d %H:%M:%S %Y"
        )
    except (TypeError, ValueError, OSError, OverflowError) as error:
        record_preflight({"reason": "recorded listener start identity could not be parsed",
                          "exception_type": type(error).__name__, "recorded_start": recorded_start,
                          "api_task_cwd_contract": cwd_contract})
        return False

    def identity_probe(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
        except BaseException as error:
            return subprocess.CompletedProcess(args, -1, "", type(error).__name__)

    start_result = identity_probe(["ps", "-p", str(listener_pid), "-o", "lstart="], 5)
    adapter_command_result = identity_probe(["ps", "-p", str(child_pid), "-o", "command="], 5)
    listener_command_result = identity_probe(["ps", "-p", str(listener_pid), "-o", "command="], 5)
    listener_executable_result = identity_probe(
        ["lsof", "-a", "-p", str(listener_pid), "-d", "txt", "-Fn"], 10)
    actual_start = start_result.stdout.strip()
    adapter_command = adapter_command_result.stdout.strip()
    listener_command = listener_command_result.stdout.strip()
    listener_executable_paths = [line[1:] for line in listener_executable_result.stdout.splitlines()
                                 if line.startswith("n")]
    api_binary_matches = False
    listener_executable: dict[str, object] = {
        "observed_paths": listener_executable_paths,
        "error": "expected private API binary identity was not supplied",
    }
    if isinstance(expected_api_binary, dict):
        api_binary_matches, listener_executable = process_executable_matches(
            listener_executable_paths,
            Path(expected_api_binary.get("binary_path", "")),
            str(expected_api_binary.get("binary_sha256", "")),
        )
    try:
        listener_command_words = shlex.split(listener_command)
        listener_command_parse_error = None
    except ValueError as error:
        listener_command_words = []
        listener_command_parse_error = type(error).__name__
    listener_command_binary = {"observed": listener_command_words[0] if listener_command_words else None,
                               "canonical_path": None, "expected_canonical_path": None,
                               "error": listener_command_parse_error}
    listener_command_matches_private_binary = False
    if isinstance(expected_api_binary, dict) and listener_command_words:
        try:
            observed_command_binary = Path(listener_command_words[0]).resolve(strict=True)
            expected_command_binary = Path(expected_api_binary.get("binary_path", "")).resolve(strict=True)
            listener_command_binary.update({
                "canonical_path": str(observed_command_binary),
                "expected_canonical_path": str(expected_command_binary),
            })
            listener_command_matches_private_binary = observed_command_binary == expected_command_binary
        except (OSError, RuntimeError) as error:
            listener_command_binary["error"] = type(error).__name__
    adapter_cwd_result = identity_probe(
        ["lsof", "-a", "-p", str(child_pid), "-d", "cwd", "-Fn"], 10)
    listener_cwd_result = identity_probe(
        ["lsof", "-a", "-p", str(listener_pid), "-d", "cwd", "-Fn"], 10)
    adapter_cwd_paths = [line[1:] for line in adapter_cwd_result.stdout.splitlines() if line.startswith("n")]
    listener_cwd_paths = [line[1:] for line in listener_cwd_result.stdout.splitlines() if line.startswith("n")]
    adapter_cwd_matches, adapter_cwd = process_cwd_matches(
        adapter_cwd_paths, Path(cwd_contract["checkout_root"]),
    )
    listener_cwd_matches, listener_cwd = process_cwd_matches(
        listener_cwd_paths, Path(cwd_contract["expected_cwd"]),
    )
    _, port_text = old_address.rsplit(":", 1)
    socket_result = identity_probe(
        ["lsof", "-nP", "-iTCP:" + port_text, "-sTCP:LISTEN", "-Fpcn"], 10)
    socket_owner = None
    current_socket_row = None
    for line in socket_result.stdout.splitlines():
        if line.startswith("p"):
            if current_socket_row and listener_pid == current_socket_row.get("pid"):
                socket_owner = current_socket_row
            try:
                current_socket_row = {"pid": int(line[1:]), "command": None, "names": []}
            except ValueError:
                current_socket_row = None
        elif current_socket_row is not None and line.startswith("c"):
            current_socket_row["command"] = line[1:]
        elif current_socket_row is not None and line.startswith("n"):
            current_socket_row["names"].append(line[1:])
    if current_socket_row and listener_pid == current_socket_row.get("pid"):
        socket_owner = current_socket_row
    identity_checks = {
        "recorded_start_present": bool(recorded_start),
        "start_identity_query_succeeded": start_result.returncode == 0,
        "start_second_matches": start_result.returncode == 0 and expected_start == actual_start,
        "adapter_command_query_succeeded": adapter_command_result.returncode == 0,
        "adapter_command_matches": (adapter_command_result.returncode == 0
                                     and str(REPO) in adapter_command
                                     and "managed-rust-listener" in adapter_command),
        "listener_command_query_succeeded": listener_command_result.returncode == 0,
        "adapter_working_directory_matches": (
            adapter_cwd_result.returncode == 0 and adapter_cwd_matches
        ),
        "listener_working_directory_matches": (
            listener_cwd_result.returncode == 0 and listener_cwd_matches
        ),
        "kernel_socket_owned_by_recorded_listener": (
            socket_result.returncode in (0, 1)
            and socket_owner is not None
            and socket_owner.get("command") == "acme-api"
            and f"127.0.0.1:{port_text}" in socket_owner.get("names", [])
        ),
        "listener_command_is_reference_api": (
            listener_command_result.returncode == 0
            and listener_command_matches_private_binary
        ),
        "listener_executable_matches_private_build": (
            listener_executable_result.returncode == 0 and api_binary_matches
        ),
    }
    if not all(identity_checks.values()):
        record_preflight({
            "reason": "exact process identity check failed before signal",
            "child_pid": child_pid,
            "listener_pid": listener_pid,
            "recorded_supervisor_pid": supervisor_pid,
            "observed_child_parent_pid": child_parent,
            "observed_listener_parent_pid": listener_parent,
            "identity_checks": identity_checks,
            "recorded_start": recorded_start,
            "expected_ps_start": expected_start,
            "actual_ps_start": actual_start,
            "identity_probe_exit_codes": {
                "listener_start": start_result.returncode,
                "adapter_command": adapter_command_result.returncode,
                "listener_command": listener_command_result.returncode,
                "listener_executable": listener_executable_result.returncode,
                "adapter_cwd": adapter_cwd_result.returncode,
                "listener_cwd": listener_cwd_result.returncode,
                "kernel_socket": socket_result.returncode,
            },
            "adapter_command": adapter_command[:500],
            "listener_command": listener_command[:500],
            "listener_command_parse_error": listener_command_parse_error,
            "listener_command_binary": listener_command_binary,
            "expected_api_binary": expected_api_binary,
            "listener_executable": listener_executable,
            "api_task_cwd_contract": cwd_contract,
            "adapter_cwd": adapter_cwd,
            "listener_cwd": listener_cwd,
            "socket_owner": socket_owner,
        })
        print(
            "BLOCKED Reference API restart before signal: exact process identity check failed "
            f"(adapter_pid={child_pid}, listener_pid={listener_pid}, "
            f"parents={child_parent}/{listener_parent}, checks={identity_checks}, "
            f"recorded_start={recorded_start}, expected_ps_start={expected_start!r}, "
            f"actual_ps_start={actual_start!r}, adapter_command={adapter_command[:500]!r}, "
            f"listener_command={listener_command[:500]!r}, "
            f"expected_listener_cwd={cwd_contract['expected_cwd']!r}, "
            f"adapter_cwd={adapter_cwd!r}, listener_cwd={listener_cwd!r}, "
            f"socket_owner={socket_owner!r})",
            flush=True,
        )
        return False

    latest_ancestry = process_parent_map()
    latest_listener_ancestry = process_ancestry_chain(listener_pid, child_pid, latest_ancestry)
    if latest_ancestry.get(child_pid) != supervisor_pid or latest_listener_ancestry != listener_ancestry:
        record_preflight({
            "reason": "recorded listener ancestry changed during restart preflight",
            "child_pid": child_pid,
            "listener_pid": listener_pid,
            "recorded_supervisor_pid": supervisor_pid,
            "observed_child_parent_pid": latest_ancestry.get(child_pid),
            "observed_listener_ancestry": latest_listener_ancestry,
            "identity_checks": identity_checks,
            "identity_probe_exit_codes": {
                "listener_start": start_result.returncode,
                "adapter_command": adapter_command_result.returncode,
                "listener_command": listener_command_result.returncode,
                "listener_executable": listener_executable_result.returncode,
                "adapter_cwd": adapter_cwd_result.returncode,
                "listener_cwd": listener_cwd_result.returncode,
                "kernel_socket": socket_result.returncode,
            },
            "expected_api_binary": expected_api_binary,
            "listener_command_binary": listener_command_binary,
            "listener_executable": listener_executable,
            "api_task_cwd_contract": cwd_contract,
            "adapter_cwd": adapter_cwd,
            "listener_cwd": listener_cwd,
        })
        print("BLOCKED Reference API restart before signal: recorded ancestry changed during preflight", flush=True)
        return False

    if not record_preflight({
        "status": "preflight_passed",
        "decision": "signal_authorized",
        "child_pid": child_pid,
        "listener_pid": listener_pid,
        "recorded_supervisor_pid": supervisor_pid,
        "observed_child_parent_pid": child_parent,
        "observed_listener_parent_pid": listener_parent,
        "observed_listener_ancestry": latest_listener_ancestry,
        "identity_checks": identity_checks,
        "recorded_start": recorded_start,
        "expected_ps_start": expected_start,
        "actual_ps_start": actual_start,
        "identity_probe_exit_codes": {
            "listener_start": start_result.returncode,
            "adapter_command": adapter_command_result.returncode,
            "listener_command": listener_command_result.returncode,
            "listener_executable": listener_executable_result.returncode,
            "adapter_cwd": adapter_cwd_result.returncode,
            "listener_cwd": listener_cwd_result.returncode,
            "kernel_socket": socket_result.returncode,
        },
        "adapter_command": adapter_command[:500],
        "listener_command": listener_command[:500],
        "listener_command_parse_error": listener_command_parse_error,
        "listener_command_binary": listener_command_binary,
        "expected_api_binary": expected_api_binary,
        "listener_executable": listener_executable,
        "api_task_cwd_contract": cwd_contract,
        "adapter_cwd": adapter_cwd,
        "listener_cwd": listener_cwd,
        "socket_owner": socket_owner,
        "api_generation": before_api.get("generation"),
        "api_address": old_address,
    }):
        print("BLOCKED Reference API restart before signal: durable identity receipt failed", flush=True)
        return False

    try:
        # The adapter declares restart="on-failure". SIGTERM is graceful and
        # may make the application exit with status 0, which does not exercise
        # that policy. After checking the exact recorded process start,
        # ancestry, command, cwd, and socket ownership above, SIGKILL the
        # disposable API listener so the adapter reports a non-zero child exit.
        os.kill(listener_pid, signal.SIGKILL)
        LAST_API_RESTART_DIAGNOSTIC["signal_sent"] = True
        if diagnostic_sink is not None:
            diagnostic_sink(
                "api_restart_signal_sent",
                listener_pid=listener_pid,
                signal="SIGKILL",
                api_generation=before_api.get("generation"),
                api_address=old_address,
            )
    except ProcessLookupError:
        LAST_API_RESTART_DIAGNOSTIC["reason"] = "recorded socket-owning listener exited before the targeted signal"
        LAST_API_RESTART_DIAGNOSTIC["listener_pid"] = listener_pid
        print("BLOCKED Reference API restart: recorded listener exited before the targeted signal", flush=True)
        return False
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
        LAST_API_RESTART_DIAGNOSTIC.update({
            "phase": "waiting_for_ready_generation",
            "reason": "no new ready generation appeared within 150 seconds",
            "termination_signal": "SIGKILL",
            "child_pid": child_pid,
            "old_generation": before_api["generation"],
            "old_address": old_address,
        })
        print("BLOCKED Reference API restart: no new ready generation appeared within 150 seconds", flush=True)
        return False

    report_path = api_path.parent / f"api.{restarted['generation']}.listener-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["generation"] == restarted["generation"]
    assert report["address"] == restarted["address"]

    route_deadline = time.monotonic() + 30
    current_gateway = None
    route = None
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
        LAST_API_RESTART_DIAGNOSTIC.update({
            "phase": "route_replacement",
            "reason": "new listener did not replace the owned route target",
            "generation": restarted["generation"],
            "address": restarted["address"],
            "route_target": route.get("target") if route else None,
        })
        print("BLOCKED Reference API restart: new listener did not replace the owned route target", flush=True)
        return False

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
        LAST_API_RESTART_DIAGNOSTIC = {
            "status": "passed",
            "phase": "complete",
            "old_generation": before_api["generation"],
            "new_generation": restarted["generation"],
            "old_address": old_address,
            "new_address": restarted["address"],
            "route_target": route["target"],
            "dependent_generations_changed": dependent_changes,
        }
        print("PASS owned API child restart, new endpoint report, route replacement, and dependent restarts", flush=True)
        return True
    else:
        LAST_API_RESTART_DIAGNOSTIC = {
            "status": "unproven",
            "phase": "dependency_propagation",
            "reason": "API generation/route was ready but address change or dependent restart was not established",
            "old_generation": before_api["generation"],
            "new_generation": restarted["generation"],
            "old_address": old_address,
            "new_address": restarted["address"],
            "route_target": route["target"],
            "dependent_generations_changed": dependent_changes,
        }
        print("PARTIAL restart proof: the API generation/route is ready; endpoint change or dependent restart was not established", flush=True)
        return False


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

    fixture_public_origin_observations(main, states, gateway_port, context)

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

def prove_worktree_plans(checkouts: list[Path], env: dict[str, str] | None = None) -> None:
    scopes = []
    domains = []
    for checkout in checkouts:
        scope = effigy_json(checkout, "container", "scope", "--json", env=env)["result"]["scope"]
        hosts = effigy_json(checkout, "container", "hosts", "--json", env=env)["result"]
        scopes.append(scope.get("token") or "primary")
        domains.append(hosts["base_domain"]["effective"])
        assert all(
            route["origin"] is None or route["origin"].startswith("https://")
            for route in hosts["routes"]
        )
        run([EFFIGY, "--repo", str(checkout), "dev", "--plan"], env=env, timeout=30)

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
    fixture_scripts = (
        REPO / "scripts/dev/profile_launcher.py",
        REPO / "scripts/silo_fixture.py",
        REPO / "scripts/reference_storage_probe.py",
        REPO / "scripts/qualify-silo-artifacts.py",
        REPO / "scripts/qualify-reference-container.py",
        REPO / "scripts/qualify-reference-runtime.py",
        REPO / "scripts/qualify-reference-optin.py",
        REPO / "scripts/dev/profile_admission_test.py",
        REPO / "scripts/qualification/managed-listener-probe.py",
    )
    vite_adapter = REPO / "scripts/dev/managed-vite-listener.mjs"
    compile(rust_adapter.read_text(encoding="utf-8"), str(rust_adapter), "exec")
    for fixture_script in fixture_scripts:
        compile(fixture_script.read_text(encoding="utf-8"), str(fixture_script), "exec")
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
        "const apiUrl = makeUrl(routes.api)",
        "EFFIGY_PROFILE_GATEWAY_HTTPS_PORT",
        "EFFIGY_PROFILE_PUBLIC_ORIGIN",
        "EFFIGY_PROFILE_PUBLIC_URL",
        "EFFIGY_PROFILE_PUBLIC_CONFIG_GENERATOR",
        "allowedHosts: [publicUrl.hostname]",
        "protocol: publicUrl.protocol === \"https:\" ? \"wss\" : \"ws\"",
    ):
        assert token in vite_source, f"Vite adapter is missing {token}"
    origin_hook = REPO / "scripts/dev/sveltekit-public-origin.mjs"
    assert origin_hook.is_file()
    node_hook = subprocess.run(
        ["node", "--check", str(origin_hook)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if node_hook.returncode != 0:
        raise RuntimeError(f"SvelteKit public-origin helper syntax check failed: {node_hook.stderr.strip()}")
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
        fixture_home = root / "home"
        fixture_home.mkdir(mode=0o700, exist_ok=True)
        fixture_env = {**os.environ, "HOME": str(fixture_home)}
        for checkout in checkouts:
            point_bundle_at_task_branch(checkout)
            bundle = effigy_json(checkout, "bundle", "inspect", "--json")["result"]
            assert bundle["source"]["source_type"] == "path"
            assert Path(bundle["source"]["source_path"]).resolve() == REPO.resolve()
        prove_private_pilot_receipts(checkouts)
        prove_worktree_plans(checkouts, fixture_env)
        prove_real_adapter_task_plans(checkouts[0])
        return 0

    root = Path(tempfile.mkdtemp(prefix="underlay-reference-profile-"))
    print(f"PRIVATE FIXTURE ROOT: {root}", flush=True)
    try:
        checkouts = make_reference_instances(source, root)
        version = run([EFFIGY, "--version"], timeout=30).stdout.strip()
        print(f"EFFIGY: {version}", flush=True)
        prove_reference_configuration(checkouts)
        fixture_home = root / "home"
        fixture_home.mkdir(mode=0o700)
        initialize_reference_fixture_secrets(checkouts, {**os.environ, "HOME": str(fixture_home)})
        prove_worktree_plans(checkouts, {**os.environ, "HOME": str(fixture_home)})
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
