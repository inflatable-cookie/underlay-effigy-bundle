#!/usr/bin/env python3
"""Qualify the bundle boundary for host-process development profiles."""

from __future__ import annotations

import http.client
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from qualification_runtime import require_effigy_binary


REPO = Path(__file__).resolve().parents[1]
EFFIGY: Path | None = None


RUST_SOURCE = r'''use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

fn main() {
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|error| {
        eprintln!("BIND_FAILED {error}");
        std::process::exit(23);
    });
    println!("READY rust {}", listener.local_addr().unwrap().port());
    std::io::stdout().flush().unwrap();

    let (mut stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
        line.clear();
    }
    let body = b"rust-ok";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    let mut discard = Vec::new();
    let _ = reader.read_to_end(&mut discard);
}
'''

BUN_SOURCE = r'''let server;
server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch() {
    setTimeout(() => server.stop(false), 0);
    return new Response("bun-ok");
  },
});
console.log(`READY bun ${server.port}`);
'''


def run(
    args: list[str],
    *,
    cwd: Path = REPO,
    env: dict[str, str] | None = None,
    timeout: float | None = 30,
    expected: int | None = 0,
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
    if result.stdout and show_output:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr and show_output:
        print(result.stderr.rstrip(), flush=True)
    if not show_output:
        print(
            f"OUTPUT: captured stdout={len(result.stdout)} bytes stderr={len(result.stderr)} bytes",
            flush=True,
        )
    if expected is not None and result.returncode != expected:
        raise RuntimeError(
            f"expected exit {expected}, got {result.returncode}: {' '.join(args)}"
        )
    return result


def create_checkout(path: Path, host: str, workspace: str) -> None:
    path.mkdir(parents=True)
    for package in ("app-api", "app-client", "app-admin", "app-front"):
        package_root = path / package
        package_root.mkdir()
        (package_root / "effigy.toml").write_text(
            '[tasks.health]\nrun = "true"\nrun_in = "host"\n'
            '[tasks.validate]\nrun = "true"\nrun_in = "host"\n',
            encoding="utf-8",
        )

    (path / "app-api" / "Cargo.toml").write_text(
        '[package]\nname = "profile-probe"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (path / "app-api" / "src").mkdir()
    (path / "app-api" / "src" / "main.rs").write_text(RUST_SOURCE, encoding="utf-8")
    (path / "app-front" / "package.json").write_text(
        '{"name":"profile-probe-front","private":true}\n', encoding="utf-8"
    )
    (path / "app-front" / "server.mjs").write_text(BUN_SOURCE, encoding="utf-8")
    (path / "app-admin" / "package.json").write_text(
        '{"name":"profile-probe-admin","private":true}\n', encoding="utf-8"
    )
    (path / "app-admin" / "server.mjs").write_text(BUN_SOURCE, encoding="utf-8")
    (path / workspace).mkdir()
    (path / ".gitignore").write_text(
        ".effigy/\n.qualification-target/\nCargo.lock\nnode_modules/\n",
        encoding="utf-8",
    )

    bundle_dir = json.dumps(REPO.as_posix())
    manifest = (
        "[bundle]\n"
        f"base = {{ type = \"path\", dir = {bundle_dir} }}\n"
        f'host = "{host}"\n'
        f'workspace_subdir = "{workspace}"\n'
        'databases = ["profile_probe"]\n\n'
        "[bundle.sources]\n"
        "siblings = false\n\n"
        "[containers.stack]\n"
        'driver = "colima"\n'
        'profile = "effigy"\n\n'
        '[tasks."proof:rust-listener"]\n'
        'run = "cargo run --offline --quiet --manifest-path app-api/Cargo.toml"\n'
        'run_in = "host"\n\n'
        '[tasks."proof:bun-listener"]\n'
        'run = "bun run app-front/server.mjs"\n'
        'run_in = "host"\n'
    )
    (path / "effigy.toml").write_text(manifest, encoding="utf-8")

    for package in ("app-api", "app-client", "app-admin", "app-front"):
        tasks = "[tasks.dev]\nrun = \"true\"\nrun_in = \"host\"\n"
        if package == "app-api":
            tasks += (
                '[tasks.api]\nrun = "cargo run --offline --quiet --manifest-path Cargo.toml"\n'
                'run_in = "host"\n'
                '[tasks.jobs]\nrun = "true"\nrun_in = "host"\n'
            )
        (path / package / "effigy.toml").write_text(
            '[tasks.health]\nrun = "true"\nrun_in = "host"\n'
            '[tasks.validate]\nrun = "true"\nrun_in = "host"\n'
            + tasks,
            encoding="utf-8",
        )


def create_worktrees(main: Path, root: Path) -> list[Path]:
    run(["git", "init", "-b", "main", str(main)], cwd=root)
    run(["git", "-C", str(main), "config", "user.name", "Qualification fixture"], cwd=root)
    run(
        ["git", "-C", str(main), "config", "user.email", "qualification@example.invalid"],
        cwd=root,
    )
    run(["git", "-C", str(main), "add", "."], cwd=root)
    run(["git", "-C", str(main), "commit", "-m", "private qualification fixture"], cwd=root)

    worktree_root = root / "worktrees"
    worktree_root.mkdir()
    worktrees = []
    for name in ("first", "second"):
        worktree = worktree_root / name
        run(
            ["git", "-C", str(main), "worktree", "add", "-b", f"qualification-{name}", str(worktree), "HEAD"],
            cwd=root,
        )
        worktrees.append(worktree)
    return [main, *worktrees]


def effigy_json(checkout: Path, *args: str) -> dict:
    result = run([EFFIGY, "--repo", str(checkout), *args], timeout=30, show_output=False)
    return json.loads(result.stdout)


def inspect_bundle(checkouts: list[Path]) -> None:
    main = checkouts[0]
    bundle = effigy_json(main, "bundle", "inspect", "--json")["result"]
    assert bundle["source"]["source_type"] == "path"
    assert Path(bundle["source"]["source_path"]) == REPO

    config = run(
        [EFFIGY, "--repo", str(main), "config", "--inspect"],
        timeout=30,
        show_output=False,
    ).stdout
    effective = config.split("Effective Manifest\n------------------\n", 1)[1]
    assert '[bundle.sources]\nsiblings = false' in effective
    assert 'underlay = ' not in effective and 'poodle = ' not in effective
    assert 'catalog = "workspace-rust-bun"' in effective
    assert '"41001:41001"' in effective
    assert '"41002:41002"' in effective
    assert '"41003:41003"' in effective
    assert 'project_name = "' in effective and '-underlay"' in effective

    tasks = run(
        [EFFIGY, "--repo", str(main), "tasks", "--json"],
        timeout=30,
        show_output=False,
    ).stdout
    assert "proof:rust-listener" in tasks and "proof:bun-listener" in tasks
    assert "underlay/" not in tasks and "poodle/" not in tasks
    run([EFFIGY, "--repo", str(main), "dev", "--plan"], timeout=30)

    identities = []
    domains = []
    for checkout in checkouts:
        scope = effigy_json(checkout, "container", "scope", "--json")["result"]["scope"]
        hosts = effigy_json(checkout, "container", "hosts", "--json")["result"]
        identities.append(scope.get("token") or "primary")
        domains.append(hosts["base_domain"]["effective"])
        assert all(route["origin"] is None or route["origin"].startswith("https://") for route in hosts["routes"])

    assert len(set(identities)) == len(checkouts)
    assert len(set(domains)) == len(checkouts)
    print(f"PASS private identities: {identities}", flush=True)
    print(f"PASS isolated browser domains: {domains}", flush=True)
    print("PASS siblings=false task resolution and unchanged bundle host-port defaults", flush=True)


def start_listener(checkout: Path, selector: str, label: str) -> dict:
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(checkout / ".qualification-target")
    process = subprocess.Popen(
        [EFFIGY, "--repo", str(checkout), selector],
        cwd=checkout,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.put(line.rstrip())
        lines.put(None)

    threading.Thread(target=read_output, daemon=True).start()
    return {"label": label, "process": process, "port": None, "lines": lines, "observed": []}


def wait_listener_ready(listener: dict) -> None:
    deadline = time.monotonic() + 180
    ready_port = None
    while time.monotonic() < deadline:
        try:
            line = listener["lines"].get(
                timeout=max(0.1, min(1, deadline - time.monotonic()))
            )
        except queue.Empty:
            if listener["process"].poll() is not None:
                break
            continue
        if line is None:
            break
        listener["observed"].append(line)
        match = re.search(r"READY (rust|bun) (\d+)", line)
        if match:
            ready_port = int(match.group(2))
            break
    if ready_port is None:
        raise RuntimeError(
            f"{listener['label']} did not report a listener; output={listener['observed']}"
        )
    listener["port"] = ready_port


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def query_listener(listener: dict, expected: str) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", listener["port"], timeout=10)
    connection.request("GET", "/qualification")
    response = connection.getresponse()
    body = response.read().decode("utf-8")
    connection.close()
    if response.status != 200 or body != expected:
        raise RuntimeError(
            f"{listener['label']} expected 200/{expected!r}, got {response.status}/{body!r}"
        )
    listener["process"].wait(timeout=30)
    print(
        f"PASS {listener['label']}: 127.0.0.1:{listener['port']} returned {response.status}/{body}; "
        f"child exit {listener['process'].returncode}",
        flush=True,
    )
    if listener["process"].returncode != 0:
        raise RuntimeError(f"{listener['label']} Effigy task failed")


def prove_host_listener_boundary(checkouts: list[Path]) -> None:
    surface = json.loads(
        run(
            [EFFIGY, "rhai", "surface", "--json"],
            timeout=30,
            show_output=False,
        ).stdout
    )
    gateway_functions = sorted(
        item["name"] for item in surface["result"]["functions"] if item["module"] == "gateway"
    )
    expected_gateway_functions = ["down", "setup_tls", "status", "up"]
    assert gateway_functions == expected_gateway_functions, gateway_functions
    print(f"OBSERVED gateway Rhai functions: {gateway_functions}", flush=True)

    listeners = []
    try:
        for checkout in checkouts:
            listeners.append(start_listener(checkout, "proof:rust-listener", f"{checkout.name}/rust"))
            listeners.append(start_listener(checkout, "proof:bun-listener", f"{checkout.name}/bun"))
        for listener in listeners:
            wait_listener_ready(listener)
        ports = [listener["port"] for listener in listeners]
        assert len(set(ports)) == len(ports), ports
        print(f"PASS six simultaneous host listeners got distinct OS-assigned ports: {ports}", flush=True)

        for listener in listeners:
            query_listener(listener, "rust-ok" if listener["label"].endswith("/rust") else "bun-ok")

        foreign = socket.socket()
        foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        foreign.bind(("127.0.0.1", 0))
        foreign.listen(1)
        foreign.settimeout(10)
        occupied_port = foreign.getsockname()[1]
        env = dict(os.environ)
        env["PORT"] = str(occupied_port)
        env["CARGO_TARGET_DIR"] = str(checkouts[0] / ".qualification-target")
        collision = run(
            [EFFIGY, "--repo", str(checkouts[0]), "proof:rust-listener"],
            cwd=checkouts[0],
            env=env,
            timeout=180,
            expected=None,
        )
        assert collision.returncode != 0
        assert "BIND_FAILED" in collision.stderr or "BIND_FAILED" in collision.stdout
        client = http.client.HTTPConnection("127.0.0.1", occupied_port, timeout=10)
        client.request("GET", "/foreign")
        connection, _ = foreign.accept()
        connection.recv(4096)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nforeign")
        connection.close()
        response = client.getresponse()
        body = response.read().decode("utf-8")
        client.close()
        foreign.close()
        assert response.status == 200 and body == "foreign"
        print(
            f"PASS occupied strict bind: Rust exited {collision.returncode}; "
            f"foreign listener on {occupied_port} still served {body}",
            flush=True,
        )
    finally:
        for listener in listeners:
            stop_process(listener["process"])


def private_fixture_root() -> Path:
    configured_parent = os.environ.get("UNDERLAY_PROFILE_FIXTURE_PARENT")
    shared_parent = Path.home() / "Dev" / "projects"
    if configured_parent:
        parent = Path(configured_parent).expanduser()
    elif shared_parent.is_dir():
        parent = shared_parent
    else:
        parent = Path(tempfile.gettempdir())
    if not parent.is_dir():
        raise RuntimeError(f"fixture parent is not an existing directory: {parent}")
    return Path(tempfile.mkdtemp(prefix="underlay-profile-qualification-", dir=parent))


def note_container_startup_boundary() -> None:
    print(
        "NOT RUN: this synthetic listener proof does not start a gateway or qualify browser routes; "
        "the designated Reference selector inventories private gateway and app-route receipts.",
        flush=True,
    )


def main() -> int:
    global EFFIGY
    if EFFIGY is None:
        EFFIGY = require_effigy_binary()
    token = uuid.uuid4().hex[:10]
    fixture_root = private_fixture_root()
    try:
        host = f"profile-{token}.test"
        workspace = f"fixture-{token}"
        main_checkout = fixture_root / "main"
        create_checkout(main_checkout, host, workspace)
        checkouts = create_worktrees(main_checkout, fixture_root)

        version = run([EFFIGY, "--version"], timeout=30).stdout.strip()
        print(f"Effigy: {version}", flush=True)
        inspect_bundle(checkouts)
        prove_host_listener_boundary(checkouts)
        note_container_startup_boundary()
        print(
            "QUALIFICATION: synthetic Rust/Bun listener ownership and collision checks passed; "
            "Reference app-route readiness remains subject to the pilot receipts.",
            flush=True,
        )
        return 0
    finally:
        try:
            shutil.rmtree(fixture_root)
        except OSError as error:
            raise RuntimeError(f"could not remove private fixture root {fixture_root}: {error}") from error


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"QUALIFICATION FAILED: {error}", flush=True)
        raise SystemExit(1)
