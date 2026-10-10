#!/usr/bin/env python3
"""Minimal disposable child for Effigy's managed-listener lifecycle proof."""

from __future__ import annotations

import http.server
import json
import errno
import os
import signal
import tempfile
import threading
from pathlib import Path


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Effigy did not provide {name}")
    return value


def main() -> int:
    raw_bind = required("EFFIGY_MANAGED_HOST_LISTENER_BIND")
    host, separator, raw_port = raw_bind.rpartition(":")
    if not separator or host != "127.0.0.1":
        raise RuntimeError("qualification listener requires an IPv4 loopback bind")
    requested_port = int(raw_port)
    if not 0 <= requested_port <= 65535:
        raise RuntimeError("qualification listener port is outside the TCP range")

    stopping = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stopping.set()

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, request_stop)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"effigy-managed-listener-ready"
            raw_status = os.environ.get("EFFIGY_PROFILE_PROBE_HTTP_STATUS", "200")
            try:
                status = int(raw_status)
            except ValueError as error:
                raise RuntimeError("qualification HTTP status must be numeric") from error
            if not 100 <= status <= 599:
                raise RuntimeError("qualification HTTP status is outside the HTTP status range")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    try:
        server = http.server.ThreadingHTTPServer((host, requested_port), Handler)
    except OSError as error:
        # Keep an occupied-port child alive only for the bounded ownership
        # diagnostic fixture. This gives Effigy time to observe and stop the
        # exact child instead of turning a fast bind failure into a PID race.
        # All normal launches, and every other bind error, still exit at once.
        if (
            error.errno == errno.EADDRINUSE
            and os.environ.get("EFFIGY_PROFILE_WAIT_ON_EADDRINUSE") == "1"
        ):
            print(
                f"qualification listener failed: {type(error).__name__} errno={error.errno} {error.strerror}",
                flush=True,
            )
            stopping.wait(45)
        raise
    server.daemon_threads = True
    address = server.server_address
    if requested_port and address[1] != requested_port:
        server.server_close()
        raise RuntimeError("qualification listener did not retain its strict requested port")

    report_path = Path(required("EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE"))
    generation = required("EFFIGY_MANAGED_HOST_LISTENER_GENERATION")
    report_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {
        "schema": "effigy.managed.host-listener-report.v1",
        "generation": generation,
        "address": f"{address[0]}:{address[1]}",
    }
    descriptor, temporary = tempfile.mkstemp(prefix=".listener-report-", dir=report_path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as report:
            json.dump(payload, report, separators=(",", ":"))
            report.flush()
            os.fsync(report.fileno())
        os.replace(temporary, report_path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        server.server_close()
        raise

    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    try:
        stopping.wait()
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        print(
            f"qualification listener failed: {type(error).__name__} errno={error.errno} {error.strerror}",
            flush=True,
        )
        raise SystemExit(1)
    except (RuntimeError, ValueError) as error:
        print(f"qualification listener failed: {type(error).__name__}", flush=True)
        raise SystemExit(1)
