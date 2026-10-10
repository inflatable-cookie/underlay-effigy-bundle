"""Actual Reference media upload/finalisation against a fresh private Silo.

Responses, tokens, presigned queries and fixture credentials stay in memory.
Only operation/status and byte equality enter the durable receipt.
"""
import base64
import hashlib
import json
import secrets
import ssl
from urllib.parse import quote, urlsplit


def prove_reference_upload(runtime, checkout, env, states, gateway_root, gateway_port, minio_port):
    context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
    api_domain = states["api"]["route_domain"]
    origin = f'https://{states["admin"]["route_domain"]}:{gateway_port}'
    outcomes = []
    token = None

    def request(domain, method, path, body=None, headers=None, require_cors=False):
        connection = runtime.REFERENCE.GatewayHTTPSConnection(domain, gateway_port, context)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            if require_cors and response.getheader("Access-Control-Allow-Origin") != origin:
                raise RuntimeError("Reference browser upload response did not allow its fixed admin origin")
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise RuntimeError("Reference storage response exceeded the bounded probe limit")
            return response.status, data
        finally:
            connection.close()

    def api(method, path, payload=None):
        headers = {"Host": f"{api_domain}:{gateway_port}", "Origin": origin,
                   "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        status, body = request(api_domain, method, path,
                               json.dumps(payload).encode() if payload is not None else None, headers)
        outcomes.append({"operation": path.split("?")[0], "method": method, "status": status})
        if not 200 <= status < 300:
            # Never echo the body, token or presigned URL on a failed probe.
            raise RuntimeError(f"Reference storage {method} {path.split('?')[0]} returned HTTP {status}")
        return json.loads(body) if body else {}

    email = "silo-qualification@example.invalid"
    password = secrets.token_urlsafe(24)
    api("POST", "/v1/auth/register", {"email": email, "password": password, "display_name": "Silo qualification"})
    # Grant only this newly registered account in this fresh fixture database.
    # Existing seed credentials and operator auth are not used.
    sql = "UPDATE auth.users SET role='admin' WHERE email='silo-qualification@example.invalid';"
    runtime.run([runtime.EFFIGY, "--repo", str(checkout), "container", "hybrid", "shell",
                 "--service", "postgres", "--command",
                 'psql -v ON_ERROR_STOP=1 -U postgres -d acme -c ' + runtime.shlex.quote(sql)],
                cwd=checkout, env=env, timeout=60, print_output=False)
    session = api("POST", "/v1/auth/login", {"email": email, "password": password})
    token = session["data"]["access_token"]
    media = api("POST", "/v1/admin/media", {"kind": "image", "visibility": "public",
                "title": "Disposable Silo qualification", "original_filename": "qualification.png"})["data"]
    media_id = media["id"]
    payload = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a0Z8AAAAASUVORK5CYII=")
    initiated = api("POST", f"/v1/admin/media/{media_id}/versions/initiate-upload",
                    {"content_type": "image/png", "content_length": len(payload)})
    plan = initiated["upload_plan"]
    upload = urlsplit(plan["upload_url"])
    s3_domain = runtime.route_domains(runtime.effigy_json(runtime.EFFIGY, checkout, env, "container", "hosts", "--json"))["s3"]
    if upload.scheme != "https" or upload.hostname != s3_domain or upload.port != gateway_port or plan["method"] != "PUT":
        raise RuntimeError("Reference upload plan did not use the registered private Silo HTTPS authority and PUT")
    headers = dict(plan["headers"])
    headers.update({"Origin": origin, "Host": f"{s3_domain}:{gateway_port}"})
    status, _ = request(s3_domain, "PUT", upload.path + "?" + upload.query, payload, headers, require_cors=True)
    if status not in (200, 201):
        raise RuntimeError(f"Reference presigned Silo upload returned HTTP {status}")
    finalised = api("POST", f'/v1/admin/media/{media_id}/versions/{initiated["version_id"]}/finalise-upload',
                   {"sha256": hashlib.sha256(payload).hexdigest(), "content_type": "image/png"})
    version = finalised["version"]
    if version["state"] != "ready":
        raise RuntimeError("Reference finalisation did not publish a ready media version")
    object_path = "/acme-media/" + quote(version["object_key"], safe="/")
    get_status, _, received = runtime._s3_request(minio_port, "GET", object_path)
    if get_status != 200 or received != payload:
        raise RuntimeError(f"Reference finalised Silo object GET returned {get_status} or changed bytes")
    delete_status, _, _ = runtime._s3_request(minio_port, "DELETE", object_path)
    if delete_status not in (200, 204):
        raise RuntimeError(f"Reference finalised Silo object DELETE returned {delete_status}")
    return {"status": "passed", "api_operations": outcomes, "presigned_upload_status": status,
            "presigned_authority": f"https://{s3_domain}:{gateway_port}", "finalised_state": "ready",
            "signed_get_status": get_status, "signed_delete_status": delete_status, "bytes_equal": True,
            "credential_or_presigned_query_recorded": False}
