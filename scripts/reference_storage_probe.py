"""Actual Reference media upload/finalisation against a fresh private Silo.

Responses, tokens, presigned queries and fixture credentials stay in memory.
Only operation/status and byte equality enter the durable receipt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit
import auth_operation


_FRAMING_HEADERS = ("content-length", "transfer-encoding", "connection", "content-type")
_MAX_LOG_BYTES = 24 * 1024
_MAX_LOG_LINES = 80
_MAX_ARTIFACT_BYTES = 24 * 1024
_AUTH_TRACE_TARGET = "underlay_profile_auth_diagnostic"



class StorageDiagnosticJournal:
    """Append-only, private, redacted phase evidence outside the disposable fixture."""

    def __init__(self, path: Path, fixture_root: Path):
        requested = path.expanduser()
        if requested.name != "storage-diagnostics.jsonl":
            raise ValueError("storage diagnostics must use the fixed journal filename")
        directory = requested.parent.resolve(strict=True)
        fixture = fixture_root.resolve(strict=True)
        try:
            directory.relative_to(fixture)
        except ValueError:
            pass
        else:
            raise RuntimeError("storage diagnostics must be outside the disposable fixture root")
        directory_stat = directory.stat()
        if (not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != os.geteuid()
                or stat.S_IMODE(directory_stat.st_mode) != 0o700):
            raise RuntimeError("storage diagnostic directory must be owned by this user and mode 0700")
        self.path = directory / requested.name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(self.path, flags, 0o600)
        os.fchmod(self._fd, 0o600)
        self._bytes = 0
        self._capacity_refused = False
        self._snapshot_seen = {}
        self._duplicates = {"listener_probe_snapshot":0,"managed_transition_snapshot":0}
        self._sequence = 0
        self._operation = 0
        self._started: dict[str, int] = {}

    def assert_admitted(self):
        if self._capacity_refused:
            raise RuntimeError("diagnostic_capacity_refused")

    def append(self, event: str, **fields) -> None:
        self.assert_admitted()
        # Only byte-equivalent typed snapshots collapse; fresh reads/validation
        # still happen. Changed owners, tuples, causes or refusal outcomes persist.
        if event in self._duplicates:
            stable={key:value for key,value in fields.items()
                    if key not in ("observation_sequence","observation_monotonic_ns")}
            digest=hashlib.sha256(json.dumps(stable,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            key=(event,digest)
            if key in self._snapshot_seen:
                self._duplicates[event]+=1
                self._snapshot_seen[key]+=1
                return
            if len(self._snapshot_seen)>=256:
                self.append("diagnostic_capacity_refused",reason="distinct_snapshot_limit",limit=256)
                self._capacity_refused=True
                raise RuntimeError("diagnostic_capacity_refused")
            self._snapshot_seen[key]=0
        self._sequence += 1
        record = {
            "schema": "underlay.reference-storage-diagnostic.v1",
            "sequence": self._sequence,
            "event": event,
            "utc": datetime.now(timezone.utc).isoformat(),
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        info=os.fstat(self._fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
                or info.st_size!=self._bytes):
            raise RuntimeError("diagnostic_journal_identity_refused")
        if self._bytes+len(payload)>128*1024-(1024 if event=="duplicate_snapshot_aggregate" else 2048):
            self._capacity_refused=True
            refusal=(json.dumps({"schema":"underlay.reference-storage-diagnostic.v1",
                "event":"diagnostic_capacity_refused","bytes":self._bytes,
                "requested_bytes":len(payload),"cap_bytes":128*1024,
                "duplicate_observations":self._duplicates},sort_keys=True)+"\n").encode()
            os.write(self._fd,refusal);os.fsync(self._fd)
            raise RuntimeError("diagnostic_capacity_refused")
        offset = 0
        while offset < len(payload):
            written=os.write(self._fd,payload[offset:])
            if not written:raise RuntimeError("diagnostic_journal_write_refused")
            offset+=written
        self._bytes+=len(payload)
        os.fsync(self._fd)

    def begin(self, operation: str, method: str, path_template: str, *,
              public_name: str | None, connect_address: str) -> str:
        if (not path_template.startswith("/") or "//" in path_template or "?" in path_template
                or "://" in path_template
                or re.search(r"[0-9a-f]{8}-[0-9a-f-]{27,}", path_template, re.I)):
            raise ValueError("diagnostic path template must be a redacted path without query or instance IDs")
        self._operation += 1
        op_id = f"storage-{self._operation:02d}"
        self._started[op_id] = time.monotonic_ns()
        self.append("operation", operation_id=op_id, operation=operation, method=method,
                    path_template=path_template, public_name=public_name,
                    connect_address=connect_address, phase="before_request")
        return op_id

    def phase(self, op_id: str, operation: str, method: str, path_template: str,
              phase: str, *, status: int | None = None,
              framing: dict[str, str] | None = None, body_bytes: int | None = None,
              body_bytes_over_limit: bool | None = None) -> None:
        started = self._started[op_id]
        fields = {
            "operation_id": op_id, "operation": operation, "method": method,
            "path_template": path_template, "phase": phase,
            "elapsed_ms": round((time.monotonic_ns() - started) / 1_000_000, 3),
        }
        if status is not None:
            fields["status"] = status
        if framing:
            fields["framing"] = framing
        if body_bytes is not None:
            fields["body_bytes"] = min(body_bytes, 1_048_576)
            fields["body_bytes_over_limit"] = bool(body_bytes_over_limit)
        self.append("operation_phase", **fields)

    def exception(self, op_id: str, operation: str, method: str, path_template: str,
                  phase: str, error: BaseException, *, status: int | None = None) -> None:
        fields = {
            "operation_id": op_id, "operation": operation, "method": method,
            "path_template": path_template, "phase": phase,
            "exception_type": type(error).__name__,
            "elapsed_ms": round((time.monotonic_ns() - self._started[op_id]) / 1_000_000, 3),
        }
        error_number = getattr(error, "errno", None)
        if isinstance(error_number, int):
            fields["errno"] = error_number
        if status is not None:
            fields["status"] = status
        self.append("operation_exception", **fields)

    def write_log(self, name: str, lines: list[str]) -> str:
        if Path(name).name != name or not re.fullmatch(r"[a-z0-9-]+\.log", name):
            raise ValueError("diagnostic log name must be a simple lowercase .log filename")
        safe_lines = []
        for line in lines[-_MAX_LOG_LINES:]:
            safe = sanitize_service_log_line(line)
            if safe:
                safe_lines.append(safe)
        payload = "\n".join(safe_lines).encode("utf-8", errors="replace")[:_MAX_LOG_BYTES]
        target = self.path.parent / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        self.append("service_log_captured", service=name.removesuffix(".log"),
                    path=str(target), bytes=len(payload), lines=len(safe_lines))
        return str(target)

    def write_artifact(self, name: str, payload: bytes) -> str:
        if name != "reference-auth-diagnostic.patch" or len(payload) > _MAX_ARTIFACT_BYTES:
            raise ValueError("diagnostic artifact must be the bounded Reference auth fixture patch")
        target = self.path.parent / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        digest = hashlib.sha256(payload).hexdigest()
        self.append("diagnostic_artifact_captured", name=name, path=str(target),
                    bytes=len(payload), sha256=digest)
        return str(target)

    def close(self) -> None:
        if self._fd >= 0:
            try:
                if any(self._duplicates.values()) and not self._capacity_refused:
                    self.append("duplicate_snapshot_aggregate",counts=self._duplicates,
                        distinct_source_payloads=len(self._snapshot_seen),
                        omitted_byte_equivalent_observations=sum(self._duplicates.values()),
                        cache_authority=False)
            finally:
                os.close(self._fd)
                self._fd = -1


def sanitize_service_log_line(line: str) -> str:
    """Keep useful bounded log context without URLs, bodies, or credentials."""
    if re.search(r"(?i)authorization|bearer\s|password|secret|access[_ -]?key|token|signature|presigned", line):
        return "[sensitive log line omitted]"
    if re.search(r"(?i)request[_ -]?body|response[_ -]?body|payload|<\?xml|<error\b|<message\b", line):
        return "[body-bearing log line omitted]"
    if re.search(r"(?i)\b(?:request|response)\s*[:=]\s*(?:\{|\[|\"|')", line):
        return "[body-bearing log line omitted]"
    line = re.sub(r"(?i)(/acme-media/)[^?\s\"'<>]+", r"\1<object-key>", line)
    line = re.sub(r"(\S+)\?[^\s\"'<>]+", r"\1?[query omitted]", line)
    line = re.sub(r"https?://[^\s\"'<>]+", "[url omitted]", line)
    line = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<id>", line)
    line = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<email>", line)
    line = re.sub(r"(?i)(qualification-local-only|minioadmin)", "[credential omitted]", line)
    line = re.sub(r'(?i)(user_id\s*[=:]\s*)"?[0-9a-f-]{36}', r'\1<id>', line)
    if _AUTH_TRACE_TARGET in line:
        try: observed=auth_operation.decode_trace(line.rstrip('\n').encode('utf-8'))
        except auth_operation.AuthRefusal:
            return "[auth diagnostic line omitted: protocol refusal]"
        return ("AUTH_DIAGNOSTIC correlation=fixture-auth-login "
                f"phase={observed['phase']} elapsed_ms={observed['elapsed_ms']} outcome={observed['outcome']}")
    if not re.search(r"(?i)error|warn|timeout|request|response|status|listening|shutdown|ready|started|stopped|configur|db_configured", line):
        return ""
    return line[:1000]


def framing_metadata(response) -> dict[str, str]:
    allowed = {}
    for key in _FRAMING_HEADERS:
        value = response.getheader(key)
        if value is not None:
            allowed[key] = str(value)[:128]
    return allowed


def prove_reference_upload(runtime, checkout, env, states, gateway_root, gateway_port, minio_port,
                           *, service_container="hybrid", diagnostics: StorageDiagnosticJournal | None = None,
                           diagnostic_context: dict | None = None):
    context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
    api_domain = states["api"]["route_domain"]
    origin = f'https://{states["admin"]["route_domain"]}:{gateway_port}'
    outcomes = []
    token = None

    if diagnostics is not None:
        diagnostics.append("storage_probe_context", **(diagnostic_context or {}))

    def request(domain, method, path, body=None, headers=None, require_cors=False,
                *, operation, path_template):
        connection = runtime.REFERENCE.GatewayHTTPSConnection(domain, gateway_port, context)
        op_id = diagnostics.begin(operation, method, path_template, public_name=domain,
                                  connect_address=f"127.0.0.1:{gateway_port}") if diagnostics else None
        phase = "before_request"
        response = None
        status = None
        try:
            connection.request(method, path, body=body, headers=headers or {})
            phase = "request_sent"
            if diagnostics:
                diagnostics.phase(op_id, operation, method, path_template, phase)
            phase = "before_response_headers"
            if diagnostics:
                diagnostics.phase(op_id, operation, method, path_template, phase)
            response = connection.getresponse()
            status = response.status
            phase = "response_headers_received"
            if diagnostics:
                diagnostics.phase(op_id, operation, method, path_template, phase, status=status,
                                  framing=framing_metadata(response))
            if require_cors and response.getheader("Access-Control-Allow-Origin") != origin:
                raise RuntimeError("Reference browser upload response did not allow its fixed admin origin")
            phase = "before_response_body"
            if diagnostics:
                diagnostics.phase(op_id, operation, method, path_template, phase, status=status)
            data = response.read(1024 * 1024 + 1)
            phase = "response_body_received"
            if diagnostics:
                diagnostics.phase(op_id, operation, method, path_template, phase, status=status,
                                  body_bytes=len(data), body_bytes_over_limit=len(data) > 1024 * 1024)
            if len(data) > 1024 * 1024:
                raise RuntimeError("Reference storage response exceeded the bounded probe limit")
            return response.status, data, op_id
        except BaseException as error:
            if diagnostics and op_id:
                diagnostics.exception(op_id, operation, method, path_template, phase, error,
                                      status=status)
            raise
        finally:
            connection.close()

    def api(operation, method, path, path_template, payload=None):
        headers = {"Host": f"{api_domain}:{gateway_port}", "Origin": origin,
                   "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if operation in ("register", "login"):
            if diagnostics is None:
                raise RuntimeError("auth operation requires a durable private diagnostic sink")
            op_id = diagnostics.begin(operation, method, path_template, public_name=api_domain,
                                      connect_address=f"127.0.0.1:{gateway_port}")
            def emit(event, **fields):
                diagnostics.append("auth_" + event, operation=operation, operation_id=op_id, **fields)
            api_log = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy/api.log"
            auth_operation.capture(api_log, checkout.resolve(), emit, operation=operation)
            try:
                result = auth_operation.request(api_domain, gateway_port, gateway_root / "ca/rootCA.pem",
                                                operation, payload, origin, emit)
            finally:
                observations,complete = auth_operation.capture(api_log, checkout.resolve(), emit, post=True, operation=operation)
                if operation == "login" and not complete:
                    raise auth_operation.AuthRefusal("protocol")
            outcomes.append({"operation":operation, "method":method, "status":200,
                             "absolute_budget_ms":20000, "session_schema_valid":True})
            return result
        status, body, op_id = request(api_domain, method, path,
                                      json.dumps(payload).encode() if payload is not None else None, headers,
                                      operation=operation, path_template=path_template)
        outcomes.append({"operation": operation, "method": method, "status": status})
        if not 200 <= status < 300:
            if diagnostics:
                diagnostics.append("operation_exception", operation_id=op_id, operation=operation,
                                   method=method, path_template=path_template,
                                   phase="http_status_validation", exception_type="UnexpectedHTTPStatus",
                                   status=status)
            # Never echo the body, token or presigned URL on a failed probe.
            raise RuntimeError(f"Reference storage {operation} returned HTTP {status}")
        try:
            result = json.loads(body) if body else {}
        except BaseException as error:
            if diagnostics:
                diagnostics.append("operation_exception", operation_id=op_id,
                                   operation=operation, method=method,
                                   path_template=path_template, phase="response_json_decode",
                                   exception_type=type(error).__name__, status=status)
            raise
        if diagnostics:
            diagnostics.phase(op_id, operation, method, path_template,
                              "response_json_decoded", status=status)
        return result

    email = "silo-qualification@example.invalid"
    password = secrets.token_urlsafe(24)
    api("register", "POST", "/v1/auth/register", "/v1/auth/register",
        {"email": email, "password": password, "display_name": "Silo qualification"})
    # Grant only this newly registered account in this fresh fixture database.
    # Existing seed credentials and operator auth are not used.
    sql = "UPDATE auth.users SET role='admin' WHERE email='silo-qualification@example.invalid';"
    if diagnostics:
        diagnostics.append("service_setup_started", operation="fixture_admin_role_grant", service="postgres")
    try:
        runtime.run([runtime.EFFIGY, "--repo", str(checkout), "container", service_container, "shell",
                     "--service", "postgres", "--command",
                     'psql -v ON_ERROR_STOP=1 -U postgres -d acme -c ' + runtime.shlex.quote(sql)],
                    cwd=checkout, env=env, timeout=60, print_output=False)
    except BaseException as error:
        if diagnostics:
            diagnostics.append("service_setup_failed", operation="fixture_admin_role_grant",
                               service="postgres", exception_type=type(error).__name__)
        raise
    if diagnostics:
        diagnostics.append("service_setup_completed", operation="fixture_admin_role_grant", service="postgres")
    session = api("login", "POST", "/v1/auth/login", "/v1/auth/login",
                  {"email": email, "password": password})
    token = session["data"]["access_token"]
    media = api("media_create", "POST", "/v1/admin/media", "/v1/admin/media", {"kind": "image", "visibility": "public",
                "title": "Disposable Silo qualification", "original_filename": "qualification.png"})["data"]
    media_id = media["id"]
    payload = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a0Z8AAAAASUVORK5CYII=")
    initiated = api("upload_initiate", "POST", f"/v1/admin/media/{media_id}/versions/initiate-upload",
                    "/v1/admin/media/<media-id>/versions/initiate-upload",
                    {"content_type": "image/png", "content_length": len(payload)})
    plan = initiated["upload_plan"]
    upload = urlsplit(plan["upload_url"])
    service_hosts = runtime.effigy_json(
        runtime.EFFIGY, checkout, env, "container", service_container, "hosts", "--json"
    )
    s3_routes = [
        route.get("effective")
        for route in service_hosts.get("routes", [])
        if route.get("declared") == "s3.acme.test"
        and isinstance(route.get("effective"), str)
        and route.get("effective")
    ]
    if len(s3_routes) != 1:
        raise RuntimeError("Reference hybrid service host map omitted its unique S3 route")
    s3_domain = s3_routes[0]
    if upload.scheme != "https" or upload.hostname != s3_domain or upload.port != gateway_port or plan["method"] != "PUT":
        raise RuntimeError("Reference upload plan did not use the registered private Silo HTTPS authority and PUT")
    headers = dict(plan["headers"])
    headers.update({"Origin": origin, "Host": f"{s3_domain}:{gateway_port}"})
    status, _, upload_operation_id = request(
        s3_domain, "PUT", upload.path + "?" + upload.query, payload, headers,
        require_cors=True, operation="presigned_put", path_template="/acme-media/<object-key>")
    if status not in (200, 201):
        if diagnostics:
            diagnostics.append("operation_exception", operation_id=upload_operation_id,
                               operation="presigned_put", method="PUT",
                               path_template="/acme-media/<object-key>",
                               phase="http_status_validation", exception_type="UnexpectedHTTPStatus",
                               status=status)
        raise RuntimeError(f"Reference presigned Silo upload returned HTTP {status}")
    finalised = api("upload_finalise", "POST",
                    f'/v1/admin/media/{media_id}/versions/{initiated["version_id"]}/finalise-upload',
                    "/v1/admin/media/<media-id>/versions/<version-id>/finalise-upload",
                   {"sha256": hashlib.sha256(payload).hexdigest(), "content_type": "image/png"})
    version = finalised["version"]
    if version["state"] != "ready":
        if diagnostics:
            diagnostics.append("operation_exception", operation="upload_finalise", method="POST",
                               path_template="/v1/admin/media/<media-id>/versions/<version-id>/finalise-upload",
                               phase="response_validation", exception_type="UnexpectedMediaState",
                               status=outcomes[-1]["status"])
        raise RuntimeError("Reference finalisation did not publish a ready media version")
    object_path = "/acme-media/" + quote(version["object_key"], safe="/")
    get_status, _, received = runtime._s3_request(
        minio_port, "GET", object_path, diagnostics=diagnostics,
        diagnostic_operation="signed_s3_get", diagnostic_path_template="/acme-media/<object-key>",
    )
    if get_status != 200 or received != payload:
        if diagnostics:
            diagnostics.append("operation_exception", operation="signed_s3_get", method="GET",
                               path_template="/acme-media/<object-key>", phase="response_validation",
                               exception_type="UnexpectedHTTPStatus" if get_status != 200 else "ObjectBytesMismatch",
                               status=get_status)
        raise RuntimeError(f"Reference finalised Silo object GET returned {get_status} or changed bytes")
    delete_status, _, _ = runtime._s3_request(
        minio_port, "DELETE", object_path, diagnostics=diagnostics,
        diagnostic_operation="signed_s3_delete", diagnostic_path_template="/acme-media/<object-key>",
    )
    if delete_status not in (200, 204):
        if diagnostics:
            diagnostics.append("operation_exception", operation="signed_s3_delete", method="DELETE",
                               path_template="/acme-media/<object-key>", phase="response_validation",
                               exception_type="UnexpectedHTTPStatus", status=delete_status)
        raise RuntimeError(f"Reference finalised Silo object DELETE returned {delete_status}")
    return {"status": "passed", "api_operations": outcomes, "presigned_upload_status": status,
            "presigned_authority": f"https://{s3_domain}:{gateway_port}", "finalised_state": "ready",
            "signed_get_status": get_status, "signed_delete_status": delete_status, "bytes_equal": True,
            "credential_or_presigned_query_recorded": False}
