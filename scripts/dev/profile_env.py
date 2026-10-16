#!/usr/bin/env python3
"""Environment and lifecycle glue for the opt-in host profiles.

Effigy owns isolation: it scopes hostnames, ports and loopback aliases per
checkout, supervises the managed listeners and reports the effective names
through `effigy container <name> hosts --json`. This helper translates that
report into the variables Underlay apps already read, bootstraps the
profile's object store, and runs the bounded `dev:test` cycle.

    profile_env.py exec <container> [--self ROLE] -- COMMAND...
    profile_env.py bootstrap <container>
    profile_env.py test <container> --task SELECTOR --timeout SECS
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROLES = ("api", "front", "admin", "s3")
DATABASE_USER = "postgres"
DATABASE_PASSWORD = "secret"  # catalog postgres default; local loopback only
SILO_ACCESS_KEY = "minioadmin"  # catalog silo default; local loopback only
SILO_SECRET_KEY = "minioadmin"
POSTGRES_PORT = 5432
SMTP_PORT = 1025
S3_PORT = 9000
SERVICE_WAIT_SECS = 120


class ProfileError(RuntimeError):
    pass


def repo_root() -> Path:
    explicit = os.environ.get("EFFIGY_PROFILE_REPO")
    if explicit:
        return Path(explicit).resolve()
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    )
    if top.returncode != 0:
        raise ProfileError("profile commands must run inside the consumer checkout")
    return Path(top.stdout.strip()).resolve()


def nested_environment() -> dict[str, str]:
    """Caller environment minus Effigy's internal and per-listener variables.

    A managed child inherits them from its supervisor; passed on, they change
    a nested `effigy` call's output shape and listener identity.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("EFFIGY_INTERNAL_", "EFFIGY_MANAGED_HOST_"))
    }


def effigy(repo: Path, *args: str, timeout: float | None = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["effigy", *args, "--repo", str(repo)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=nested_environment(),
    )


def hosts_report(repo: Path, container: str) -> dict:
    result = effigy(repo, "container", container, "hosts", "--json")
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ProfileError(
            f"`effigy container {container} hosts` failed; this profile needs an Effigy build "
            f"with managed host listeners.\n{result.stderr.strip()}"
        ) from None
    report = envelope.get("result") if isinstance(envelope, dict) else None
    if not envelope.get("ok") or not isinstance(report, dict):
        error = envelope.get("error") or {}
        detail = error.get("message") if isinstance(error, dict) else error
        raise ProfileError(
            f"`effigy container {container} hosts` refused: {detail or result.stderr.strip()}"
        )
    return report


def status_report(repo: Path, container: str) -> dict:
    result = effigy(repo, "container", container, "status", "--json")
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ProfileError(f"`effigy container {container} status` failed:\n{result.stderr.strip()}") from None
    report = envelope.get("result") if isinstance(envelope, dict) else None
    if not envelope.get("ok") or not isinstance(report, dict):
        raise ProfileError(f"`effigy container {container} status` refused: {envelope.get('error')}")
    return report


def published_port(status: dict, service: str, container_port: int) -> int:
    """Host loopback port Effigy published for `service`'s `container_port`.

    Accepts the runtime's `[ADDR:]HOST->CONTAINER[/proto]` forms, including
    ranges such as `11940-11941->9000-9001/tcp`.
    """
    for entry in status.get("services", []):
        if entry.get("name") != service:
            continue
        for mapping in entry.get("ports", []):
            host, _, inner = mapping.partition("->")
            inner = inner.split("/", 1)[0]
            host = host.rsplit(":", 1)[-1]
            host_lo, _, host_hi = host.partition("-")
            inner_lo, _, inner_hi = inner.partition("-")
            if not (host_lo.isdigit() and inner_lo.isdigit()):
                continue
            offset = container_port - int(inner_lo)
            if 0 <= offset <= int(inner_hi or inner_lo) - int(inner_lo):
                return int(host_lo) + offset
    raise ProfileError(f"the profile publishes no host port for {service}:{container_port}")


def tcp_ready(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def silo_ready(port: int) -> bool:
    # The runtime's port forwarder accepts TCP before Silo listens, so ask
    # Silo itself.
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/minio/health/live", timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


SERVICE_PROBES = {
    "postgres": (POSTGRES_PORT, tcp_ready),
    "mailpit": (SMTP_PORT, tcp_ready),
    "minio": (S3_PORT, silo_ready),
}


def wait_for_services(
    status: dict,
    probes: dict = SERVICE_PROBES,
    timeout: float = SERVICE_WAIT_SECS,
    clock=time.monotonic,
    sleep=time.sleep,
) -> None:
    """Wait until each service answers on its published loopback port.

    Effigy starts host processes once the containers launch, which can be
    before a service is ready; an app that sets up storage at startup would
    otherwise race it.
    """
    pending = {
        service: (published_port(status, service, port), probe)
        for service, (port, probe) in probes.items()
    }
    deadline = clock() + timeout
    while pending:
        for service, (port, probe) in list(pending.items()):
            if probe(port):
                del pending[service]
        if not pending:
            return
        if clock() >= deadline:
            raise ProfileError(
                f"services not ready after {timeout:.0f}s: {', '.join(sorted(pending))}"
            )
        sleep(0.5)


def declared_domains(env: dict[str, str]) -> dict[str, str]:
    domains = {}
    for role in ROLES:
        value = env.get(f"EFFIGY_PROFILE_{role.upper()}_DECLARED")
        if not value:
            raise ProfileError(f"EFFIGY_PROFILE_{role.upper()}_DECLARED is not set by the bundle")
        domains[role] = value
    return domains


def shared_apex(hosts: list[str]) -> str:
    """Longest common dot-suffix of the app hosts, e.g. `acme.test`."""
    labels = [host.split(".") for host in hosts]
    shared: list[str] = []
    for parts in zip(*(reversed(label) for label in labels)):
        if len(set(parts)) != 1:
            break
        shared.insert(0, parts[0])
    if len(shared) < 2:
        raise ProfileError(f"app hosts {hosts} share no registrable apex for cookies")
    return ".".join(shared)


def app_environment(report: dict, status: dict, declared: dict[str, str], database: str) -> dict[str, str]:
    """Map Effigy's host and status reports onto the Underlay app variables.

    Public names come from the effective host map; service connections use
    the published loopback ports, so they need no gateway DNS.
    """
    http = {route["declared"]: route for route in report.get("routes", []) if route.get("kind") == "http"}
    origins = {}
    for role, domain in declared.items():
        route = http.get(domain)
        if route is None:
            raise ProfileError(f"the profile declares no `{domain}` route for {role}")
        origins[role] = route["origin"]

    api = urlsplit(origins["api"])
    https_port = api.port or 443
    return {
        "PUBLIC_HOST": api.hostname,
        "PUBLIC_SCHEME": "https",
        "PUBLIC_PORT": str(https_port),
        "CORS_ORIGINS": f"{origins['front']},{origins['admin']}",
        # Effigy's cookie_domain follows the first service route, not the
        # app listeners, so derive it from the app hosts themselves.
        "COOKIE_DOMAIN": "." + shared_apex(
            [urlsplit(origins[role]).hostname for role in ("api", "front", "admin")]
        ),
        "DATABASE_URL": (
            f"postgres://{DATABASE_USER}:{DATABASE_PASSWORD}"
            f"@127.0.0.1:{published_port(status, 'postgres', POSTGRES_PORT)}/{database}"
        ),
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": str(published_port(status, "mailpit", SMTP_PORT)),
        "EFFIGY_PROFILE_S3_ENDPOINT": f"http://127.0.0.1:{published_port(status, 'minio', S3_PORT)}",
        # The profile's own Silo, not a deployed store: its catalog
        # credentials, and no instance-metadata lookup on a miss.
        "AWS_ACCESS_KEY_ID": SILO_ACCESS_KEY,
        "AWS_SECRET_ACCESS_KEY": SILO_SECRET_KEY,
        "AWS_EC2_METADATA_DISABLED": "true",
        "EFFIGY_PROFILE_API_PUBLIC_URL": origins["api"],
        "EFFIGY_PROFILE_FRONT_PUBLIC_URL": origins["front"],
        "EFFIGY_PROFILE_ADMIN_PUBLIC_URL": origins["admin"],
        "EFFIGY_PROFILE_S3_PUBLIC_URL": origins["s3"],
        "EFFIGY_PROFILE_GATEWAY_HTTPS_PORT": str(https_port),
    }


def gateway_ca_file(env: dict[str, str], mkcert_caroot=None) -> str | None:
    """CA that signs the gateway's certificates, for host-side HTTPS clients.

    The workspace image installs it for container apps; host Node/Bun
    processes need it via NODE_EXTRA_CA_CERTS to call their own API through
    the gateway. A private gateway keeps its CA in its state root; the shared
    gateway uses mkcert's root.
    """
    private_root = env.get("EFFIGY_GATEWAY_PRIVATE_STATE_ROOT")
    if private_root:
        candidate = Path(private_root) / "ca" / "rootCA.pem"
        return str(candidate) if candidate.is_file() else None
    if mkcert_caroot is None:
        try:
            result = subprocess.run(
                ["mkcert", "-CAROOT"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        mkcert_caroot = result.stdout.strip() if result.returncode == 0 else ""
    candidate = Path(mkcert_caroot) / "rootCA.pem" if mkcert_caroot else None
    return str(candidate) if candidate is not None and candidate.is_file() else None


def resolved_environment(
    repo: Path, container: str, env: dict[str, str], wait: bool = False
) -> dict[str, str]:
    database = env.get("EFFIGY_PROFILE_DATABASE")
    if not database:
        raise ProfileError("EFFIGY_PROFILE_DATABASE is not set by the bundle")
    status = status_report(repo, container)
    if wait:
        wait_for_services(status)
    values = app_environment(hosts_report(repo, container), status, declared_domains(env), database)
    if not env.get("NODE_EXTRA_CA_CERTS"):
        ca = gateway_ca_file(env)
        if ca:
            values["NODE_EXTRA_CA_CERTS"] = ca
    return values


def cors_document(origins: list[str]) -> str:
    rules = "".join(f"<AllowedOrigin>{origin}</AllowedOrigin>" for origin in origins)
    return (
        "<CORSConfiguration><CORSRule>"
        + rules
        + "<AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod>"
        "<AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader>"
        "<ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-request-id</ExposeHeader>"
        "<ExposeHeader>x-amz-id-2</ExposeHeader><MaxAgeSeconds>3000</MaxAgeSeconds>"
        "</CORSRule></CORSConfiguration>"
    )


def bootstrap_script(bucket: str, origins: list[str]) -> str:
    return (
        "set -eu\n"
        "until mc ready local >/dev/null 2>&1; do sleep 1; done\n"
        f"mc mb local/{bucket} --ignore-existing >/dev/null\n"
        f"mc anonymous set download local/{bucket} >/dev/null\n"
        "cat > /tmp/effigy-silo-cors.xml <<'EOF'\n"
        + cors_document(origins)
        + "\nEOF\n"
        f"mc cors set local/{bucket} /tmp/effigy-silo-cors.xml >/dev/null\n"
    )


def bootstrap(repo: Path, container: str, env: dict[str, str]) -> None:
    bucket = env.get("EFFIGY_PROFILE_BUCKET")
    if not bucket:
        raise ProfileError("EFFIGY_PROFILE_BUCKET is not set by the bundle")
    values = resolved_environment(repo, container, env)
    origins = [values["EFFIGY_PROFILE_FRONT_PUBLIC_URL"], values["EFFIGY_PROFILE_ADMIN_PUBLIC_URL"]]
    result = effigy(
        repo,
        "container", container, "shell",
        "--service", "minio",
        "--command", bootstrap_script(bucket, origins),
        timeout=180,
    )
    if result.returncode != 0:
        raise ProfileError(f"object store bootstrap failed:\n{result.stderr.strip()}")
    print(f"[ok] {container}: bucket {bucket} ready for {', '.join(origins)}")


def run_test(repo: Path, container: str, task: str, timeout: int, env: dict[str, str]) -> int:
    if not task:
        raise ProfileError(
            "set the bundle input `profiles.test_task` to the selector dev:test should run"
        )
    steps = (("reset", ("container", container, "reset")), ("up", ("container", container, "up", "--detach")))
    try:
        for name, args in steps:
            result = effigy(repo, *args, timeout=1800)
            if result.returncode != 0:
                raise ProfileError(f"dev:test {name} failed:\n{result.stderr.strip() or result.stdout.strip()}")
        bootstrap(repo, container, env)
        child_env = {**nested_environment(), **resolved_environment(repo, container, env)}
        try:
            return subprocess.run(
                ["effigy", task, "--repo", str(repo)], env=child_env, timeout=timeout, check=False
            ).returncode
        except subprocess.TimeoutExpired:
            print(f"dev:test: `{task}` exceeded {timeout}s", file=sys.stderr)
            return 124
    finally:
        down = effigy(repo, "container", container, "down", timeout=600)
        if down.returncode != 0:
            print(f"dev:test: teardown needs attention:\n{down.stderr.strip()}", file=sys.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("exec")
    run.add_argument("container")
    run.add_argument("--self", choices=("front", "admin"))
    run.add_argument("argv", nargs=argparse.REMAINDER)
    boot = commands.add_parser("bootstrap")
    boot.add_argument("container")
    test = commands.add_parser("test")
    test.add_argument("container")
    test.add_argument("--task", default="")
    test.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args(argv)

    env = dict(os.environ)
    repo = repo_root()
    if args.command == "bootstrap":
        bootstrap(repo, args.container, env)
        return 0
    if args.command == "test":
        return run_test(repo, args.container, args.task, args.timeout, env)

    command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not command:
        raise ProfileError("usage: profile_env.py exec <container> [--self ROLE] -- COMMAND...")
    env.update(resolved_environment(repo, args.container, env, wait=True))
    if args.self:
        env["EFFIGY_PROFILE_PUBLIC_URL"] = env[f"EFFIGY_PROFILE_{args.self.upper()}_PUBLIC_URL"]
    os.execvpe(command[0], command, env)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except ProfileError as error:
        print(f"profile: {error}", file=sys.stderr)
        sys.exit(1)
