#!/usr/bin/env python3
"""Run a Rust task as an Effigy managed host listener.

The application owns its socket: Effigy's bind preference is passed through
HOST/PORT, and the wrapper reports the actual loopback socket found in the
task's descendant process tree. Effigy still performs the authoritative
socket-ownership and HTTP-readiness checks before publishing a route.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


BIND_ENV = "EFFIGY_MANAGED_HOST_LISTENER_BIND"
REPORT_ENV = "EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE"
GENERATION_ENV = "EFFIGY_MANAGED_HOST_LISTENER_GENERATION"


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Effigy did not provide {name}")
    return value


def bind_preference() -> tuple[str, int]:
    raw = required_env(BIND_ENV)
    host, separator, port_text = raw.rpartition(":")
    if not separator or host != "127.0.0.1":
        raise RuntimeError(f"managed Rust listener requires an IPv4 loopback bind, got {raw!r}")
    try:
        port = int(port_text)
    except ValueError as error:
        raise RuntimeError(f"invalid managed listener port in {raw!r}") from error
    if not 0 <= port <= 65535:
        raise RuntimeError(f"managed listener port is outside the TCP range: {port}")
    return host, port


def descendant_pids(root_pid: int) -> list[int]:
    listing = subprocess.run(
        ["ps", "-axo", "pid=,ppid="],
        check=True,
        capture_output=True,
        text=True,
    )
    children: dict[int, list[int]] = {}
    for line in listing.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            pid, ppid = map(int, fields)
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)

    found: list[int] = []
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        found.append(pid)
        pending.extend(children.get(pid, ()))
    return found


def owned_loopback_listener(root_pid: int, host: str) -> str | None:
    pids = descendant_pids(root_pid)
    result = subprocess.run(
        [
            "lsof",
            "-nP",
            "-a",
            "-p",
            ",".join(map(str, pids)),
            "-iTCP",
            "-sTCP:LISTEN",
            "-F",
            "n",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"lsof could not inspect the Rust task's listeners: {result.stderr.strip()}")
    matches = set()
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"n127\.0\.0\.1:(\d+)", line)
        if match:
            matches.add(f"{host}:{int(match.group(1))}")
    if len(matches) > 1:
        raise RuntimeError(f"Rust task opened multiple loopback listeners: {sorted(matches)}")
    return next(iter(matches), None)


def write_report(address: str) -> None:
    report_path = Path(required_env(REPORT_ENV))
    generation = required_env(GENERATION_ENV)
    report_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {
        "schema": "effigy.managed.host-listener-report.v1",
        "generation": generation,
        "address": address,
    }
    fd, temporary = tempfile.mkstemp(prefix=".listener-report-", dir=report_path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, report_path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str]) -> int:
    if not argv or argv[0] != "--" or len(argv) < 2:
        raise RuntimeError("usage: managed-rust-listener.py -- <Effigy selector command...>")
    host, requested_port = bind_preference()
    command = argv[1:]
    environment = os.environ.copy()
    environment["HOST"] = host
    environment["PORT"] = str(requested_port)
    child = subprocess.Popen(command, env=environment)
    stopping = False

    def stop_child(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        if child.poll() is None:
            child.send_signal(signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop_child)

    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            if child.poll() is not None:
                return child.returncode
            address = owned_loopback_listener(child.pid, host)
            if address is not None:
                actual_port = int(address.rpartition(":")[2])
                if requested_port != 0 and actual_port != requested_port:
                    raise RuntimeError(
                        f"Rust task ignored strict bind port {requested_port} and listened on {actual_port}"
                    )
                write_report(address)
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Rust task did not expose an owned IPv4 loopback listener within 90 seconds")

        return child.wait()
    finally:
        if stopping and child.poll() is None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"managed Rust listener adapter failed: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
