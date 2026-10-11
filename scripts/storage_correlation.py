"""Finite, secret-free projections for the owned Silo write/read diagnosis."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ERROR_CODES = {"NoSuchKey", "NoSuchBucket", "AccessDenied", "SignatureDoesNotMatch",
               "InvalidAccessKeyId", "InvalidRequest", "InternalError", "SlowDown"}


def safe_framing(response):
    patterns = {"Content-Length": r"[0-9]{1,12}", "Transfer-Encoding": r"chunked",
                "Connection": r"close|keep-alive", "Content-Type": r"(?:application/(?:xml|json|octet-stream)|text/plain)(?:; charset=utf-8)?"}
    result = {}
    for name, pattern in patterns.items():
        value = response.getheader(name)
        if value is not None:
            result[name.lower()] = value.lower() if re.fullmatch(pattern, value.lower()) else "unclassified"
    return result


def s3_error(body):
    result = {"error_code": "unknown"}
    if len(body) > 16384 or b"<!" in body:
        return result
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return result
    if root.tag != "Error":
        return result
    code = root.findtext("Code")
    if code in ERROR_CODES:
        result["error_code"] = code
    request = root.findtext("RequestId")
    if request and re.fullmatch(r"[A-Za-z0-9-]{1,128}", request):
        result["request_id_sha256"] = hashlib.sha256(request.encode()).hexdigest()
    return result


def json_records(output):
    """Effigy shell adds human headers; retain only complete JSON records in memory."""
    records = []
    for line in output.splitlines():
        if line.startswith("{"):
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("invalid MC record")
            records.append(value)
    if not records:
        raise ValueError("missing MC JSON record")
    return records


def alias_projection(output):
    records = json_records(output)
    if len(records) != 1:
        raise ValueError("ambiguous MC alias")
    record = records[0]
    if record.get("status") != "success" or record.get("alias") != "local":
        raise ValueError("negative MC alias result")
    url = urlsplit(record.get("URL", record.get("url", "")))
    if url.scheme != "http" or url.hostname != "silo" or url.port != 9000 or url.path not in ("", "/"):
        raise ValueError("unexpected MC endpoint")
    return {"alias": "local", "endpoint": "http://silo:9000",
            "config_scope": "client-container:/root/.mc", "credentials_recorded": False}


def stat_projection(output):
    records = json_records(output)
    if len(records) != 1 or records[0].get("status") != "success":
        raise ValueError("negative or ambiguous MC stat")
    size = records[0].get("size")
    if type(size) is not int or not 0 <= size <= 1048576:
        raise ValueError("invalid MC object size")
    return {"status": "success", "size": size}


def address_projection(output):
    values = []
    for line in output.splitlines():
        for field in line.split():
            try:
                address = ipaddress.ip_address(field)
            except ValueError:
                continue
            if address.version == 4 and address.is_private:
                values.append(str(address))
    values = sorted(set(values))
    if not values:
        raise ValueError("missing server/DNS address")
    return values


def minimal_policy(policy):
    if not isinstance(policy, dict) or policy.get("driver") != "colima" or policy.get("profile") != "effigy":
        raise ValueError("unsupported production service policy")
    services = policy.get("services")
    if not isinstance(services, dict) or services.get("silo") != {"catalog": "silo"} or services.get("silo_client") != {"catalog": "silo-mc"}:
        raise ValueError("production Silo declarations changed")
    if (policy.get('host') != {'publish_address':'127.0.0.1'}
            or policy.get('working_dir') != '/' or policy.get('startup') != 'detached'
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,100}', policy.get('project_name', ''))):
        raise ValueError('unsafe production service scope')
    result = {key: policy[key] for key in ("driver", "profile", "startup", "project_name", "working_dir", "host")}
    result.update(primary_service="silo", services={name: services[name] for name in ("silo", "silo_client")}, host_processes=[])
    return result


def hosts_projection(hosts, checkout):
    from pathlib import Path
    if (not isinstance(hosts, dict) or hosts.get('schema') != 'effigy.container.hosts.v1'
            or hosts.get('ok') is not True or hosts.get('checkout') != str(Path(checkout).resolve())):
        raise ValueError('foreign or unsupported hosts contract')
    routes = hosts.get('routes')
    if not isinstance(routes, list):
        raise ValueError('malformed hosts inventory')
    safe = []
    for route in routes:
        if not isinstance(route, dict) or route.get('kind') != 'tcp' or route.get('service') != 'silo':
            raise ValueError('unexpected service or application route')
        names = {key: route.get(key) for key in ('declared', 'effective')}
        if any(not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,200}', value) for value in names.values()):
            raise ValueError('unsafe effective hostname')
        safe.append({'kind':'tcp', 'service':'silo', **names})
    return safe


def toml_value(value):
    if isinstance(value, str):
        return json.dumps(value)
    if type(value) is bool:
        return str(value).lower()
    if type(value) is int:
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(key) + " = " + toml_value(item) for key, item in value.items()) + " }"
    raise ValueError("unsupported service policy value")


def invocation(binary, checkout, args):
    arguments = list(args)
    prefix = [binary]
    if '--json' in arguments:
        arguments.remove('--json')
        prefix.append('--json')
    # Exact-source global CLI rejects --repo for Gateway before execution.
    # Gateway ownership is selected explicitly by its private state root.
    if arguments and arguments[0] == 'gateway':
        if '--private-state-root' not in arguments:
            raise ValueError('gateway diagnosis requires explicit private state')
    else:
        prefix.extend(['--repo', str(checkout)])
    return prefix + arguments


def minimal_manifest(policy):
    return ('[containers.hybrid_services]\n'
            + '\n'.join(json.dumps(key) + ' = ' + toml_value(value) for key, value in policy.items()) + '\n')


def shell_command(command):
    # Keep the actual inner shell/pipeline exit even when Effigy maps a failed
    # child to its own generic exit 1. Commands and their output stay in memory.
    return ('set +e; ( ' + command + ' ); storage_code=$?; '
            'printf "\\nUNDERLAY_STORAGE_EXIT=%s\\n" "$storage_code"; exit "$storage_code"')


def nested_exit(output):
    values = re.findall(r'(?m)^UNDERLAY_STORAGE_EXIT=([0-9]{1,3})$', output)
    if len(values) != 1 or int(values[0]) > 255:
        return {'inner_exit': None, 'inner_exit_evidence': 'unknown'}
    return {'inner_exit': int(values[0]), 'inner_exit_evidence': 'shell_marker'}


def correlate(shell, request, journal, port, key):
    if key not in ("main-known.txt", "first-known.txt"):
        raise ValueError("unknown correlation object")
    bucket = "underlay-storage-correlation"
    payload = ("owned-storage-correlation:" + key).encode()
    journal.append("mc_alias", **alias_projection(shell("alias", "mc alias list local --json")))
    dns = address_projection(shell("dns", "getent hosts silo"))
    server = address_projection(shell("server-address", "hostname -i", service="silo"))
    journal.append("endpoint_identity", dns_addresses=dns, server_addresses=server, host_address=f"127.0.0.1:{port}")
    if dns != server:
        raise RuntimeError("client DNS and selected server address disagree")
    shell("bucket", f"mc mb local/{bucket} --ignore-existing")
    journal.append("mc_write", phase="before_pipe", key_template=key, object_sha256=hashlib.sha256(payload).hexdigest())
    shell("pipe", f"printf %s {json.dumps(payload.decode())} | mc pipe local/{bucket}/{key}")
    journal.append("mc_stat", **stat_projection(shell("stat", f"mc stat --json local/{bucket}/{key}")))
    status, _, body = request(port, "GET", f"/{bucket}/{key}", diagnostics=journal,
                              diagnostic_operation="mc_write_host_get", diagnostic_path_template="/<bucket>/<known-object>")
    journal.append("host_get", status=status, body_bytes=len(body), bytes_match=body == payload,
                   **(s3_error(body) if status >= 400 else {}))
    if status != 200 or body != payload:
        raise RuntimeError("MC write and host read disagree")
    # Overwrite the same known object to keep exactly one object per scope.
    host_key = key
    status, _, _ = request(port, "PUT", f"/{bucket}/{host_key}", payload, diagnostics=journal,
                           diagnostic_operation="host_put", diagnostic_path_template="/<bucket>/<host-object>")
    if status != 200:
        raise RuntimeError("host signed write failed")
    journal.append("host_write_mc_stat", **stat_projection(shell("host-stat", f"mc stat --json local/{bucket}/{host_key}")))
    return {"port": port, "bucket": bucket, "key": key, "payload_sha256": hashlib.sha256(payload).hexdigest()}
