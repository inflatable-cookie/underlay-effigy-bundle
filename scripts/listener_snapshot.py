"""Non-authoritative, typed snapshots of the bytes used by listener validators."""
from contextvars import ContextVar
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import transition_snapshot
from urllib.parse import urlsplit

_sink = None
_old = {}
_frame = ContextVar("listener_snapshot_frame", default=None)
_sequence = 0
_MAX_BYTES = 65536
_STATUSES = {"starting", "ready", "failed", "stopped", "stopping", "unavailable"}

_EXIT_REFUSAL = re.compile(
    r"owned child exit observation refused: category=(status_unavailable|invalid_utf8|empty|multiple_tokens|unknown_state); "
    r"owned_pid=([0-9]{1,10}); status_code=(None|Some\(-?[0-9]{1,10}\)); "
    r"stdout_bytes=([0-9]{1,10}); stdout_sha256=([0-9a-f]{64}); "
    r"stderr_bytes=([0-9]{1,10}); stderr_sha256=([0-9a-f]{64}); "
    r"utf8=(true|false); tokens=([0-9]{1,10}); elapsed_ms=([0-9]{1,10})$")
_EXIT_CAPTURE = re.compile(
    r"owned child exit observation failed: (Deadline|Launch|"
    r"(?:ReadFailure|IncompleteOutput) \{ stream: (?:Stdout|Stderr) \}|"
    r"Overflow \{ stream: (?:Stdout|Stderr), limit_bytes: [0-9]{1,10}, retained_bytes: [0-9]{1,10} \}); "
    r"owned_pid=([0-9]{1,10}); elapsed_ms=([0-9]{1,10})$")


def owned_exit_projection(line):
    """Decode only reviewed fixed structural diagnostics, never raw log text."""
    marker = "owned child exit observation "
    if marker not in line:
        return None
    message = marker + line.split(marker, 1)[1]
    match = _EXIT_REFUSAL.fullmatch(message)
    if match:
        category, pid, status, out_bytes, out_hash, err_bytes, err_hash, utf8, tokens, elapsed = match.groups()
        return {"kind": "refused", "category": category, "observed_pid": int(pid),
                "status_code": None if status == "None" else int(status[5:-1]),
                "stdout_bytes": int(out_bytes), "stdout_sha256": out_hash,
                "stderr_bytes": int(err_bytes), "stderr_sha256": err_hash,
                "utf8": utf8 == "true", "tokens": int(tokens), "elapsed_ms": int(elapsed)}
    match = _EXIT_CAPTURE.fullmatch(message)
    if match:
        failure, pid, elapsed = match.groups()
        result = {"kind": "capture_failed", "failure": failure.split(" ", 1)[0],
                  "observed_pid": int(pid), "elapsed_ms": int(elapsed)}
        if "stream:" in failure:
            result["stream"] = "stdout" if "Stdout" in failure else "stderr"
        if result["failure"] == "Overflow":
            values = re.findall(r"(?:limit_bytes|retained_bytes): ([0-9]+)", failure)
            result.update(limit_bytes=int(values[0]), retained_bytes=int(values[1]))
        return result
    return {"kind": "unclassified", "line_bytes": len(line.encode()),
            "line_sha256": hashlib.sha256(line.encode()).hexdigest()}


def capture_owned_exit_observations(checkout, sink):
    """Bounded file-only evidence before cleanup; no process/route authority."""
    for role in ("api", "front", "admin"):
        path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / (role + ".log")
        record = {"role": role, "authority": "observation_only", "path": str(path)}
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("unsafe log file")
                stream.seek(max(0, info.st_size - _MAX_BYTES))
                raw = stream.read(_MAX_BYTES)
            lines = raw.splitlines()
            if info.st_size > _MAX_BYTES and lines:
                lines = lines[1:]
            records = [item for item in (owned_exit_projection(line.decode("utf-8", errors="replace"))
                       for line in lines) if item is not None]
            record.update(read="bounded_tail", tail_bytes=len(raw), file_bytes=info.st_size,
                          device=info.st_dev, inode=info.st_ino, tail_sha256=hashlib.sha256(raw).hexdigest(),
                          tail_truncated=info.st_size > _MAX_BYTES, observations=records[-16:],
                          observations_omitted=max(0, len(records) - 16))
        except (OSError, ValueError):
            record.update(read="unavailable", observations=[])
        sink("owned_child_exit_observation_snapshot", **record)
_PHASES = {
    "report": {"not_observed", "absent", "unreadable", "unsafe", "schema_or_generation_mismatch", "invalid_address", "bind_mismatch", "accepted"},
    "ownership": {"not_reached", "no_owner_observed", "exclusive_owner_observed", "supervisor_changed", "child_unavailable", "child_changed", "supervisor_unavailable", "ancestry_changed", "ancestry_unavailable", "identity_unavailable", "identity_changed", "listener_outside_generation", "socket_inspection_failed", "exclusivity_unproven"},
    "route": {"not_reached", "prepare_failed", "ownership_changed", "publication_failed"},
    "http_probe": {"not_attempted", "connect_failed", "write_failed", "no_status_line", "malformed_status", "status_mismatch", "ready"},
}


def configure(sink):
    global _sink, _sequence
    _sink, _sequence = sink, 0
    _old.clear()


def old_states(checkout, states):
    for role in ("api", "front", "admin"):
        value = states.get(role, {})
        _old[(str(checkout), role)] = {"generation": generation(value.get("generation")),
                                     "address": address(value.get("address"))}


def generation(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) else None


def address(value):
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", value) if isinstance(value, str) else None
    return value if match and 1 <= int(match[1]) <= 65535 else None


def domain(value):
    return value if isinstance(value, str) and re.fullmatch(r"(?:api\.|admin\.|s3\.|silo\.|dbgate\.|mailpit\.)?acme(?:-w[0-9a-f]{8})?\.test", value) else None


def public_address(value):
    if not isinstance(value, str) or len(value) > 256:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not domain(parsed.hostname) or parsed.username
                or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            return None
        port = parsed.port or 443
        return f"https://{parsed.hostname}:{port}" if 1 <= port <= 65535 else None
    except ValueError:
        return None


def integer(value):
    return value if type(value) is int and 0 <= value < 2**63 else None


def start(value):
    if not isinstance(value, dict):
        return None
    return {key: integer(value.get(key)) for key in ("start_seconds", "start_microseconds")}


def _read(path):
    """Read one bounded file without following links; retain identity, never payload."""
    # Never serialize a filename derived from an unvalidated state generation.
    safe_name = (bool(re.fullmatch(r"(?:api|front|admin)(?:\.[0-9a-f]{32})?\.listener(?:-report)?\.json", path.name))
                 and path.parent.name == "effigy" and path.parent.parent.name in ("hybrid_services", "hybrid"))
    metadata = {"path": str(path) if safe_name else "unclassified_listener_path", "read": "unknown"}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("nonregular")
            raw = stream.read(_MAX_BYTES + 1)
        metadata.update(bytes_read=len(raw), device=info.st_dev, inode=info.st_ino,
                        mtime_ns=info.st_mtime_ns, sha256=hashlib.sha256(raw).hexdigest())
        if len(raw) > _MAX_BYTES:
            metadata["read"] = "oversized"
            return None, metadata, ValueError("bounded listener document exceeded limit")
        value = json.loads(raw)
        metadata["read"] = "read" if isinstance(value, dict) else "nonobject"
        return value, metadata, None
    except FileNotFoundError as error:
        metadata["read"] = "absent"
        caught = error
    except PermissionError as error:
        metadata["read"] = "permission_denied"
        caught = error
    except (UnicodeError, json.JSONDecodeError) as error:
        metadata["read"] = "malformed"
        caught = error
    except OSError as error:
        metadata["read"] = "unreadable"
        caught = error
    except ValueError as error:
        metadata["read"] = "nonregular"
        caught = error
    # Exception text/filename are never serialized.
    return None, metadata, caught


def _typed(value):
    value = value if isinstance(value, dict) else {}
    owner = value.get("route_owner")
    owner = owner if isinstance(owner, dict) else {}
    diagnostic = value.get("diagnostic")
    diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
    result = {"status": value.get("status") if isinstance(value.get("status"), str) and value["status"] in _STATUSES else "unknown",
              "generation": generation(value.get("generation")),
              "runtime_generation": generation(value.get("runtime_generation")),
              "address": address(value.get("address")), "route_domain": domain(value.get("route_domain")),
              "public_address": public_address(value.get("public_url")),
              "owner_present": bool(owner), "owner_generation": generation(owner.get("generation")),
              "owner_runtime_generation": generation(owner.get("runtime_generation")),
              "owner_target": address(owner.get("address")),
              "diagnostic": {key: diagnostic.get(key) if isinstance(diagnostic.get(key), str) and diagnostic[key] in allowed else "unknown"
                             for key, allowed in _PHASES.items()}}
    for role in ("supervisor", "child", "listener"):
        result[role + "_pid"] = integer(value.get(role + "_pid"))
        result[role + "_pgid"] = integer(value.get(role + "_pgid"))
        result[role + "_start"] = start(value.get(role + "_start_identity"))
    result["diagnostic"].update(claimed_address=address(diagnostic.get("claimed_address")),
                                observed_listener_pid=integer(diagnostic.get("observed_listener_pid")),
                                candidates_inspected=integer(diagnostic.get("candidates_inspected")),
                                http_status=integer(diagnostic.get("http_status")))
    # No dependent endpoint fields exist in pinned HostListenerState. Do not
    # invent them from environment/config; record that provenance limitation.
    result["dependent_endpoint"] = {"generation": None, "address": None, "provenance": "not_recorded_in_state"}
    return result


def _emit(record, outcome):
    global _sequence
    if _sink is None:
        return
    _sequence += 1
    _sink("listener_probe_snapshot", observation_sequence=_sequence,
          observation_monotonic_ns=time.monotonic_ns(), outcome=outcome, snapshot=record)


def read_document(path, checkout, name, helper, document):
    if _sink is None:
        return json.loads(path.read_text(encoding="utf-8"))
    value, metadata, error = _read(path)
    record = {"helper": helper, "role": name if name in ("api", "front", "admin") else "unknown",
              "checkout": str(checkout), "profile": "hybrid_services", "document": document,
              "provenance": metadata, "old": _old.get((str(checkout), name)),
              "state": _typed(value) if document == "state" else None}
    if document == "state":
        transition_snapshot.collect(checkout, name, value.get("owner") if isinstance(value, dict) else None, "listener_observation")
        gen = generation(value.get("generation")) if isinstance(value, dict) else None
        if gen and name in ("api", "front", "admin"):
            report, report_meta, _ = _read(path.parent / f"{name}.{gen}.listener-report.json")
            report = report if isinstance(report, dict) else {}
            record["report"] = {"provenance": report_meta,
                                "schema": "effigy.managed.host-listener-report.v1" if report.get("schema") == "effigy.managed.host-listener-report.v1" else "unknown",
                                "generation": generation(report.get("generation")), "address": address(report.get("address"))}
        else:
            record["report"] = {"provenance": {"read": "generation_unavailable"}}
    else:
        report = value if isinstance(value, dict) else {}
        record["report"] = {"schema": "effigy.managed.host-listener-report.v1" if report.get("schema") == "effigy.managed.host-listener-report.v1" else "unknown",
                            "generation": generation(report.get("generation")), "address": address(report.get("address"))}
    frame = _frame.get()
    if frame is not None:
        frame.append(record)
    _emit(record, "before_validation")
    if error is not None:
        raise error
    return value


def observed(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        frame = []
        token = _frame.set(frame)
        try:
            return function(*args, **kwargs)
        except BaseException:
            # Reuse the exact typed observations; never re-read after rejection.
            for record in frame:
                _emit(record, "validation_rejected")
            raise
        finally:
            _frame.reset(token)
    return wrapper
