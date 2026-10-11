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
_STATUSES = {"starting", "ready", "failed", "stopped", "stopping"}
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
