#!/usr/bin/env python3
"""Exercise the bundle's opt-in selectors in disposable Reference checkouts."""

from __future__ import annotations

import importlib.util
import errno
import json
import os
from pathlib import Path
import re
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

from qualification_runtime import require_effigy_binary


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load qualification helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REFERENCE = load_module("reference_profile_helpers", SCRIPTS / "qualify-reference-profiles.py")
RUNTIME = load_module("reference_runtime_helpers", SCRIPTS / "qualify-reference-runtime.py")
from silo_fixture import CLIENT_IMAGE, IMAGE, RELEASE, prepare_published_images  # noqa: E402


EFFIGY = require_effigy_binary()
REFERENCE.EFFIGY = EFFIGY
RUNTIME.EFFIGY = EFFIGY
RUNTIME.REFERENCE.EFFIGY = EFFIGY


def selector(checkout: Path, name: str, env: dict[str, str], timeout: int = 5400) -> subprocess.CompletedProcess[str]:
    return RUNTIME.run([EFFIGY, "--repo", str(checkout), name], cwd=checkout,
                        env=env, timeout=timeout, print_output=False)


def effigy_json(checkout: Path, env: dict[str, str], *args: str, timeout: int = 180) -> dict:
    return RUNTIME.effigy_json(EFFIGY, checkout, env, *args, timeout=timeout)


def enable_profiles(checkout: Path, source: Path) -> None:
    manifest_path = checkout / "effigy.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    bundle = REFERENCE.manifest_section(manifest, "bundle")
    if re.search(r"(?m)^profiles\s*=", bundle):
        raise RuntimeError("Reference fixture already has a profile input override")
    base = re.search(r"(?m)^base\s*=\s*\{[^\n]*\}$", bundle)
    if not base:
        raise RuntimeError("Reference fixture has no editable [bundle] declaration")
    profile_input = (
        "profiles = { enabled = true, "
        f"effigy_source = {json.dumps(str(source))}, "
        f"effigy_binary = {json.dumps(str(Path(EFFIGY).resolve()))}, "
        'test_task = "acme-api/test", test_timeout_secs = 900, silo_bucket = "acme-media" }'
    )
    bundle_offset = manifest.index(bundle)
    insert_at = bundle_offset + base.end()
    manifest = manifest[:insert_at] + "\n" + profile_input + manifest[insert_at:]
    manifest_path.write_text(manifest, encoding="utf-8")


def install_reference_silo_fixture(checkout: Path) -> None:
    """Adapt only the disposable Reference API to the profile's Silo env inputs."""
    api_source_path = checkout / "apps/acme-api/crates/api/src/main.rs"
    api_source = api_source_path.read_text(encoding="utf-8")
    old = 'let s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");'
    new = '''let mut s3_config = S3Config::minio_dev("acme-media", "https://s3.acme.test");
        if std::env::var("EFFIGY_PROFILE_SILO").as_deref() == Ok("true") {
            let endpoint = std::env::var("ACME_S3_ENDPOINT")?;
            let public = std::env::var("ACME_S3_PUBLIC_URL_BASE")?;
            s3_config = s3_config.endpoint_url(endpoint)
                .presign_url_base(public.clone())
                .public_url_base(format!("{public}/acme-media"));
        }'''
    old_count = api_source.count(old)
    new_count = api_source.count(new)
    if old_count == 1 and new_count == 0:
        api_source_path.write_text(api_source.replace(old, new, 1), encoding="utf-8")
    elif old_count == 0 and new_count == 1:
        return
    else:
        raise RuntimeError("Reference Silo fixture adapter source did not match its reviewed exact patch")


def profile_root(checkout: Path, profile: str = "hybrid") -> Path:
    key = "hybrid" if profile == "hybrid" else "test"
    return checkout / ".effigy" / "runtime" / "dev-profiles" / key / "gateway"


def route_domains(checkout: Path, env: dict[str, str]) -> dict[str, str]:
    declarations = {
        "front": "acme.test",
        "admin": "admin.acme.test",
        "api": "api.acme.test",
        "s3": "s3.acme.test",
        "silo": "silo.acme.test",
        "dbgate": "dbgate.acme.test",
        "mailpit": "mailpit.acme.test",
    }
    result: dict[str, str] = {}
    for container in ("hybrid_services",):
        hosts = effigy_json(checkout, env, "container", container, "hosts", "--json")
        for route in hosts.get("routes", []):
            declared, effective = route.get("declared"), route.get("effective")
            if not isinstance(declared, str) or not isinstance(effective, str) or not effective:
                continue
            for role, expected in declarations.items():
                if declared == expected:
                    previous = result.get(role)
                    if previous is not None and previous != effective:
                        raise RuntimeError(f"profile route {role} has conflicting effective names")
                    result[role] = effective
    # The checkout host map is authoritative for scoped public route names.
    # Listener owner state retains the declared route, so pair it with this
    # independently reported declared-to-effective mapping.
    checkout_hosts = effigy_json(checkout, env, "container", "hosts", "--json")
    checkout_routes = _effective_checkout_routes(checkout_hosts)
    for role in ("front", "admin", "api"):
        _, state = listener_state(checkout, role, env, checkout_routes)
        declared = state.get("declared_route_domain")
        expected_declared = declarations[role]
        if declared != expected_declared:
            raise RuntimeError(f"production profile listener {role} changed its declared route: {declared}")
        effective = checkout_routes.get(expected_declared)
        if not isinstance(effective, str) or not effective:
            raise RuntimeError(f"Effigy checkout host map omitted the effective route for {role}")
        if state.get("route_domain") != effective:
            raise RuntimeError(f"production profile listener {role} did not retain its current effective route")
        result[role] = effective
    missing = set(declarations) - set(result)
    if missing:
        raise RuntimeError(f"production profile selectors omitted declared routes: {sorted(missing)}")
    return result


def service_loopback_port(compose: str, service: str, target: int) -> int:
    """Read the generated loopback binding and require one exact target port."""
    block = re.search(
        rf"(?ms)^  {re.escape(service)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|^volumes:\n|\Z)",
        compose,
    )
    if block is None:
        raise RuntimeError(f"generated hybrid Compose file omitted service {service}")
    mapping = re.compile(
        rf"(?m)^\s*-\s*[\"']?127\.0\.0\.1:(\d+):{target}(?:/(?:tcp|udp))?[\"']?\s*$"
    )
    ports = [int(match.group(1)) for match in mapping.finditer(block.group(1))]
    if len(ports) != 1 or ports[0] <= 0:
        raise RuntimeError(
            f"generated hybrid Compose service {service} must publish container port {target} "
            f"once on a loopback host port; found {ports}"
        )
    return ports[0]


def gateway_context(checkout: Path, env: dict[str, str], profile: str = "hybrid") -> tuple[Path, int, dict]:
    root = profile_root(checkout, profile)
    gateway = RUNTIME.gateway_json(EFFIGY, env, root, "status")
    if gateway.get("private") is not True or gateway.get("running") is not True:
        raise RuntimeError(f"{profile} profile gateway is not running as a private instance")
    if gateway.get("tls", {}).get("ca_installed") is not False:
        raise RuntimeError("profile gateway reports system trust installation")
    address = gateway.get("https_addr")
    if not isinstance(address, str) or ":" not in address:
        raise RuntimeError("profile gateway has no discovered HTTPS address")
    return root, int(address.rsplit(":", 1)[1]), gateway


def _effective_checkout_routes(host_map: dict) -> dict[str, str]:
    routes: dict[str, str] = {}
    for item in host_map.get("routes", []):
        declared, effective = item.get("declared"), item.get("effective")
        if not isinstance(declared, str) or not isinstance(effective, str) or not effective:
            continue
        previous = routes.get(declared)
        if previous is not None and previous != effective:
            raise RuntimeError(f"Effigy checkout host map has conflicting effective names for {declared}")
        routes[declared] = effective
    return routes


def listener_state(
    checkout: Path,
    name: str,
    env: dict[str, str],
    effective_routes: dict[str, str] | None = None,
) -> tuple[Path, dict]:
    path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{name}.listener.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("status") != "ready" or not state.get("route_owner"):
        raise RuntimeError(f"production profile listener {name} is not owned and ready")
    report_path = path.parent / f"{name}.{state['generation']}.listener-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if (report.get("schema") != "effigy.managed.host-listener-report.v1"
            or report.get("generation") != state.get("generation")
            or report.get("address") != state.get("address")
            or state["route_owner"].get("address") != state.get("address")):
        raise RuntimeError(f"profile listener {name} report and owner do not match")
    declared_domain = state.get("route_domain")
    public_url = state.get("public_url")
    parsed_public_url = urlsplit(public_url) if isinstance(public_url, str) else None
    if (
        not isinstance(declared_domain, str)
        or parsed_public_url is None
        or parsed_public_url.scheme != "https"
        or not parsed_public_url.hostname
        or parsed_public_url.username
        or parsed_public_url.password
        or parsed_public_url.path not in ("", "/")
        or parsed_public_url.query
        or parsed_public_url.fragment
    ):
        raise RuntimeError(f"production profile listener {name} omitted its canonical current HTTPS public URL")
    routes = effective_routes or _effective_checkout_routes(
        effigy_json(checkout, env, "container", "hosts", "--json")
    )
    effective_domain = routes.get(declared_domain)
    if not isinstance(effective_domain, str) or not effective_domain:
        raise RuntimeError(f"Effigy checkout host map omitted the current route for {name}")
    state["declared_route_domain"] = declared_domain
    state["route_domain"] = effective_domain
    return path, state


def prove_owned_bind_exclusion(states: dict[str, dict]) -> list[dict]:
    observations = []
    for name, state in states.items():
        host, port_text = str(state["address"]).rsplit(":", 1)
        contender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            contender.bind((host, int(port_text)))
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise RuntimeError(f"foreign bind probe for owned {name} listener failed unexpectedly: {error}") from error
        else:
            raise RuntimeError(f"a second process could bind the active {name} listener address {state['address']}")
        finally:
            contender.close()
        if not RUNTIME.address_accepts_connection(state["address"]):
            raise RuntimeError(f"owned {name} listener stopped serving after the occupied-bind probe")
        observations.append({"listener": name, "address": state["address"],
                             "foreign_bind_rejected": True, "original_listener_survived": True})
    return observations


def verify_profile_runtime(checkouts: list[Path], env: dict[str, str], *, storage_only: bool) -> dict:
    service_records: dict[Path, dict] = {}
    app_records: dict[Path, dict[str, dict]] = {}
    started: set[Path] = set()
    receipts: dict = {"production_selectors": [], "instances": [], "cleanup": []}
    floor_template = '[manifest]\nminimum_effigy_version = "{% if inputs.profiles.enabled %}0.14.1{% else %}0.13.1{% endif %}"'
    if floor_template not in (ROOT / "export.toml").read_text(encoding="utf-8"):
        raise RuntimeError("profile input must raise the manifest floor only to 0.14.1")
    try:
        for checkout in checkouts:
            config = RUNTIME.run([EFFIGY, "--repo", str(checkout), "config", "--inspect"],
                                 cwd=checkout, env=env, timeout=120, print_output=False).stdout
            for block in ("[containers.hybrid_services]", "[[containers.hybrid_services.host_processes]]",
                          "[containers.disposable_test]", '[tasks."dev:hybrid"]', '[tasks."dev:test"]'):
                if block not in config:
                    raise RuntimeError(f"opt-in assembly omitted production profile declaration {block}")
            if "[bundle.sources]\nsiblings = false" not in config:
                raise RuntimeError("opt-in Reference assembly did not preserve sources.siblings=false")
            for name in ("dev:hybrid", "dev:hybrid:status", "dev:hybrid:down",
                         "dev:test", "dev:test:status", "dev:test:down"):
                plan = RUNTIME.run([EFFIGY, "--repo", str(checkout), name, "--plan"],
                                   cwd=checkout, env=env, timeout=120, print_output=False).stdout
                command = next((line.removeprefix("Command: ") for line in plan.splitlines()
                                if line.startswith("Command: ")), "")
                shell_quote = "'\"'\"'"
                expected_repo = f"--repo {shell_quote}{checkout}{shell_quote}"
                if (command.count("--repo") != 1 or expected_repo not in command
                        or "{repo}" in command or "--repo \"'" in command):
                    raise RuntimeError(f"{name} did not pass one well-formed disposable repo path to its launcher")
                receipts["production_selectors"].append(
                    {"checkout": str(checkout), "selector": name, "plan": "resolved"}
                )

        for checkout in checkouts:
            started.add(checkout)
            selector(checkout, "dev:hybrid", env, timeout=1800)
            receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid", "exit": 0})
            status = effigy_json(checkout, env, "container", "hybrid_services", "status", "--json")
            service_records[checkout] = status
            services = {str(item.get("name")): str(item.get("status")) for item in status.get("services", [])}
            for name in ("postgres", "dbgate", "mailpit", "silo", "silo_client"):
                if services.get(name, "").lower() not in {"up", "running"}:
                    raise RuntimeError(f"{checkout} production hybrid service {name} is not ready: {services.get(name)}")
            compose_path = checkout / status["compose_file"]
            compose = compose_path.read_text(encoding="utf-8")
            silo_fragment = (checkout / "infra/dev/catalog/silo/compose.fragment.yml").read_text(encoding="utf-8")
            client_fragment = (checkout / "infra/dev/catalog/silo-mc/compose.fragment.yml").read_text(encoding="utf-8")
            silo_service = re.search(r"(?ms)^  silo:\n(.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:|\Z)", compose)
            client_service = re.search(r"(?ms)^  silo_client:\n(.*?)(?=^  [A-Za-z0-9_-]+:|^volumes:|\Z)", compose)
            if ("workspace-rust-bun" in compose
                    or silo_service is None or f"image: {IMAGE}" not in silo_service.group(1)
                    or client_service is None or f"image: {CLIENT_IMAGE}" not in client_service.group(1)
                    or "image: {{ image }}" not in silo_fragment
                    or "image: {{ image }}" not in client_fragment):
                raise RuntimeError("production profile is not using the isolated pinned Silo server and client images")
            gateway_root, gateway_port, gateway = gateway_context(checkout, env)
            domains = route_domains(checkout, env)
            postgres_port = service_loopback_port(compose, "postgres", 5432)
            smtp_port = service_loopback_port(compose, "mailpit", 1025)
            silo_port = service_loopback_port(compose, "silo", 9000)
            endpoint_checks = [
                RUNTIME.wait_loopback_service(postgres_port, "postgres"),
                RUNTIME.wait_loopback_service(smtp_port, "mailpit"),
                RUNTIME.wait_loopback_service(silo_port, "minio"),
            ]
            checkout_routes = _effective_checkout_routes(
                effigy_json(checkout, env, "container", "hosts", "--json")
            )
            states = {
                name: listener_state(checkout, name, env, checkout_routes)[1]
                for name in ("api", "front", "admin")
            }
            app_records[checkout] = states
            record = {"path": str(checkout), "domains": domains, "gateway": gateway,
                      "gateway_root": str(gateway_root), "gateway_port": gateway_port,
                      "services": services, "ports": {"postgres": postgres_port, "smtp": smtp_port, "silo": silo_port},
                      "readiness": endpoint_checks, "service_compose": str(status["compose_file"])}
            receipts["instances"].append(record)
            record["listeners"] = {name: {"address": state["address"], "route": state["route_domain"],
                                           "generation": state["generation"]}
                                   for name, state in states.items()}
            record["occupied_bind_probes"] = prove_owned_bind_exclusion(states)
            selector(checkout, "dev:hybrid:status", env)
            receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid:status", "exit": 0})
            if checkout == checkouts[0]:
                selector(checkout, "dev:hybrid", env, timeout=900)
                receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid", "exit": 0,
                                                        "idempotent_existing_profile": True})

            gateway_root = Path(record["gateway_root"])
            gateway_port = int(record["gateway_port"])
            RUNTIME.observe_routes(checkout, gateway_root, env, states, gateway_port)
            RUNTIME.prove_minio(checkout, env, int(record["ports"]["silo"]),
                                f"https://{record['domains']['front']}:{gateway_port}",
                                container="hybrid_services", service="silo", client_service="silo_client",
                                bucket_name="acme-media", cleanup_bucket=False)
            silo_route = RUNTIME.prove_minio_gateway_route(checkout, gateway_root, record["domains"], gateway_port)
            if silo_route.get("status") != "passed":
                raise RuntimeError(f"profile Silo HTTPS/SNI route did not pass: {silo_route}")
            record["silo_gateway"] = silo_route
            for role, path in (("silo", "/"), ("dbgate", "/"), ("mailpit", "/")):
                route = next((item for item in RUNTIME.REFERENCE.private_gateway_status(checkout, gateway_root).get("routes", [])
                              if item.get("domain") == record["domains"][role]), None)
                if not route or route.get("tls") is not True or route.get("cert_ready") is not True:
                    raise RuntimeError(f"profile {role} service route is not privately TLS-ready")
                ca_context = ssl.create_default_context(cafile=str(gateway_root / "ca/rootCA.pem"))
                code, _, _ = REFERENCE.gateway_request(record["domains"][role], gateway_port, ca_context, path,
                                                       {"Host": f"{record['domains'][role]}:{gateway_port}"})
                if code >= 500:
                    raise RuntimeError(f"profile service HTTPS route {role} returned HTTP {code}")
            if checkout == checkouts[0]:
                upload_port = int(record["ports"]["silo"])
                receipts["reference_storage"] = RUNTIME.prove_reference_upload(
                    RUNTIME, checkout, env, states, gateway_root, gateway_port, upload_port,
                    service_container="hybrid_services")

        addresses = [state["address"] for states in app_records.values() for state in states.values()]
        routes = [state["route_domain"] for states in app_records.values() for state in states.values()]
        ports = [record["ports"]["postgres"] for record in receipts["instances"]]
        if len(addresses) != 3 * len(checkouts) or len(set(addresses)) != len(addresses):
            raise RuntimeError("production profile selectors did not allocate distinct actual host listener addresses")
        if len(set(routes)) != len(routes) or len(set(ports)) != len(ports):
            raise RuntimeError("profile routes or service loopback ports collide across Reference checkouts")
        receipts["distinct_profile_addresses"] = addresses
        receipts["distinct_profile_routes"] = routes
        receipts["distinct_postgres_ports"] = ports

        if not storage_only and len(checkouts) == 3:
            main, before = checkouts[0], app_records[checkouts[0]]
            restart_before = before["api"]
            restarted = REFERENCE.prove_reference_api_restart(
                main, Path(receipts["instances"][0]["gateway_root"]), before)
            if not restarted:
                raise RuntimeError(f"Reference API restart/dependent endpoint handoff was not proven: {REFERENCE.LAST_API_RESTART_DIAGNOSTIC}")
            _, after_api = listener_state(main, "api", env)
            if (after_api["generation"] == restart_before["generation"]
                    or after_api["address"] == restart_before["address"]):
                raise RuntimeError("API restart did not change its actual listener generation and address")
            after_states = {**before, "api": after_api}
            app_records[main] = after_states
            RUNTIME.observe_routes(main, Path(receipts["instances"][0]["gateway_root"]), env,
                                  after_states, int(receipts["instances"][0]["gateway_port"]))
            receipts["api_restart"] = {"old_generation": restart_before["generation"],
                                       "new_generation": after_api["generation"],
                                       "old_address": restart_before["address"],
                                       "new_address": after_api["address"],
                                       "dependent_front_admin_routes_reverified": True}

            foreign = [(checkout, app_records[checkout]) for checkout in checkouts[1:]]
            foreign_before = {checkout: dict(states) for checkout, states in foreign}
            selector(main, "dev:hybrid:down", env)
            receipts["production_selectors"].append({"checkout": str(main), "selector": "dev:hybrid:down", "exit": 0})
            _verify_stopped(main, app_records[main], env)
            for checkout, before_states in foreign_before.items():
                _verify_live(checkout, before_states, env)
            receipts["foreign_survivors_after_main_down"] = [str(path) for path in foreign_before]
            for checkout in checkouts[1:]:
                selector(checkout, "dev:hybrid:down", env)
                receipts["production_selectors"].append({"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
                _verify_stopped(checkout, app_records[checkout], env)

            test_checkout = main
            selector(test_checkout, "dev:test", env, timeout=5400)
            receipts["production_selectors"].append({"checkout": str(test_checkout), "selector": "dev:test", "exit": 0,
                                                      "configured_task": "acme-api/test", "timeout_secs": 900})
            test_status = effigy_json(test_checkout, env, "container", "disposable_test", "status", "--json")
            active = [service.get("name") for service in test_status.get("services", [])
                      if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}]
            test_gateway = RUNTIME.gateway_json(EFFIGY, env, profile_root(test_checkout, "test"), "status")
            if active or test_gateway.get("running") or test_gateway.get("routes"):
                raise RuntimeError(f"dev:test did not clean its disposable profile: services={active} gateway={test_gateway}")
            receipts["dev_test_cleanup"] = {"services_active": active, "gateway_running": False, "routes": []}
            selector(test_checkout, "dev:test:status", env)
            selector(test_checkout, "dev:test:down", env)
            receipts["production_selectors"].extend([
                {"checkout": str(test_checkout), "selector": "dev:test:status", "exit": 0},
                {"checkout": str(test_checkout), "selector": "dev:test:down", "exit": 0},
            ])
            manifest_path = test_checkout / "effigy.toml"
            manifest = manifest_path.read_text(encoding="utf-8")
            profile_pattern = r'(?m)^profiles = \{(?=[^\n]*enabled = true)[^\n]*test_task = "acme-api/test", test_timeout_secs = 900[^\n]*\}$'
            profile_input, count = re.subn(
                profile_pattern,
                lambda match: match.group(0).replace(
                    'test_task = "acme-api/test", test_timeout_secs = 900',
                    'test_task = "qualification:profile-interrupt", test_timeout_secs = 2',
                ),
                manifest,
                count=1,
            )
            if count != 1:
                raise RuntimeError("could not configure the bounded disposable interruption selector")
            profile_input += (
                '\n\n[tasks."qualification:profile-interrupt"]\n'
                'run = "sleep 30"\nrun_in = "host"\n'
            )
            manifest_path.write_text(profile_input, encoding="utf-8")
            interrupted = RUNTIME.run([EFFIGY, "--repo", str(test_checkout), "dev:test"],
                                      cwd=test_checkout, env=env, timeout=5400,
                                      expected=None, print_output=False)
            if interrupted.returncode == 0:
                raise RuntimeError("the bounded disposable interruption selector unexpectedly succeeded")
            interrupted_status = effigy_json(test_checkout, env, "container", "disposable_test", "status", "--json")
            interrupted_active = [service.get("name") for service in interrupted_status.get("services", [])
                                  if str(service.get("status", "")).lower() in {"up", "running", "created", "restarting"}]
            interrupted_gateway = RUNTIME.gateway_json(EFFIGY, env, profile_root(test_checkout, "test"), "status")
            if interrupted_active or interrupted_gateway.get("running") or interrupted_gateway.get("routes"):
                raise RuntimeError("timed-out dev:test action did not clean its exact disposable profile")
            receipts["bounded_action_interruption"] = {
                "selector": "qualification:profile-interrupt", "timeout_secs": 2,
                "dev_test_exit": interrupted.returncode, "services_active": interrupted_active,
                "gateway_running": False, "routes": [],
            }

        return receipts
    finally:
        # Every profile start is recorded before invocation because a failed or
        # interrupted selector may have created owned resources before returning.
        for checkout in reversed(checkouts):
            if checkout not in started:
                continue
            try:
                selector(checkout, "dev:hybrid:down", env, timeout=900)
                receipts["cleanup"].append({"checkout": str(checkout), "selector": "dev:hybrid:down", "exit": 0})
            except BaseException as error:
                receipts["cleanup"].append({"checkout": str(checkout), "selector": "dev:hybrid:down",
                                            "held": True, "error": str(error)[:600]})
                raise RuntimeError(f"production profile cleanup is held for {checkout}: {error}") from error


def _verify_live(checkout: Path, states: dict[str, dict], env: dict[str, str]) -> None:
    root, port, gateway = gateway_context(checkout, env)
    if not gateway.get("running"):
        raise RuntimeError(f"foreign profile gateway stopped after another checkout down: {checkout}")
    ca = ssl.create_default_context(cafile=str(root / "ca/rootCA.pem"))
    routes = {item.get("domain"): item for item in gateway.get("routes", [])}
    for name, before in states.items():
        _, after = listener_state(checkout, name, env)
        if any(after.get(key) != before.get(key) for key in
               ("owner", "runtime_generation", "generation", "address", "supervisor_pid", "child_pid", "listener_pid")):
            raise RuntimeError(f"foreign production profile listener {name} changed after scoped down")
        route = routes.get(after["route_domain"])
        if not route or route.get("target") != after["address"] or not RUNTIME.address_accepts_connection(after["address"]):
            raise RuntimeError(f"foreign production profile route/listener {name} was affected")
        path = "/v1/health" if name == "api" else "/"
        status, _, _ = REFERENCE.gateway_request(after["route_domain"], port, ca, path,
                                                  {"Host": f"{after['route_domain']}:{port}"})
        if status != 200:
            raise RuntimeError(f"foreign production profile HTTPS route {name} returned {status}")


def _verify_stopped(checkout: Path, states: dict[str, dict], env: dict[str, str]) -> None:
    host_status = effigy_json(checkout, env, "container", "hybrid_services", "status", "--json")
    active = host_status.get("managed_host_listeners", [])
    if any(item.get("status") == "ready" for item in active):
        raise RuntimeError(f"hybrid host listeners remain active after selector down: {checkout}")
    for name, before in states.items():
        state_path = checkout / ".effigy/runtime/host-processes/hybrid_services/effigy" / f"{name}.listener.json"
        after = json.loads(state_path.read_text(encoding="utf-8"))
        if after.get("status") != "stopped" or after.get("route_owner"):
            raise RuntimeError(f"profile listener {name} did not retain a stopped owner record")
        if RUNTIME.address_accepts_connection(before["address"]):
            raise RuntimeError(f"profile listener socket remains open after selector down: {before['address']}")
    root = profile_root(checkout)
    gateway = RUNTIME.gateway_json(EFFIGY, env, root, "status")
    if gateway.get("running") or gateway.get("routes"):
        raise RuntimeError("hybrid profile down left a private gateway or routes active")


def main() -> int:
    source = REFERENCE.reference_source()
    fixture_root = RUNTIME.mktemp_root()
    print(f"PRIVATE OPT-IN REFERENCE ROOT: {fixture_root}", flush=True)
    private_home = fixture_root / "home"
    private_home.mkdir(mode=0o700)
    colima_home = fixture_root / "colima-home"
    colima_home.mkdir(mode=0o700)
    private_cargo_home = private_home / ".cargo"
    private_cargo_home.mkdir(mode=0o700)
    private_cargo_target = private_home / ".cargo-target"
    private_cargo_target.mkdir(mode=0o700)
    runtime_env = os.environ.copy()
    real_home = runtime_env.get("HOME", str(Path.home()))
    runtime_env.update({
        "HOME": str(private_home),
        "COLIMA_HOME": str(colima_home),
        "EFFIGY_COMPOSE_BACKEND": "colima",
        "UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(fixture_root),
    })
    runtime_env["RUSTUP_HOME"] = runtime_env.get("RUSTUP_HOME") or str(Path(real_home) / ".rustup")
    runtime_env["CARGO_HOME"] = str(private_cargo_home)
    runtime_env["CARGO_TARGET_DIR"] = str(private_cargo_target)
    reference_root = private_home / "reference"
    reference_root.mkdir(mode=0o700)
    checkouts = REFERENCE.make_reference_instances(source, reference_root)
    storage_only = os.environ.get("UNDERLAY_PROFILE_STORAGE_ONLY") == "1"
    if storage_only:
        checkouts = checkouts[:1]
    for checkout in checkouts:
        REFERENCE.point_bundle_at_task_branch(checkout)
    REFERENCE.prove_reference_configuration(checkouts)
    for checkout in checkouts:
        enable_profiles(checkout, Path(os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"]).resolve(strict=True))
        bundle = RUNTIME.effigy_json(EFFIGY, checkout, runtime_env, "bundle", "inspect", "--json")
        if bundle.get("inputs", {}).get("profiles", {}).get("enabled") is not True:
            # `bundle inspect` versions differ in output shape; the effective
            # manifest assertion below remains the authoritative assembly check.
            inspected = RUNTIME.run([EFFIGY, "--repo", str(checkout), "config", "--inspect"],
                                    cwd=checkout, env=runtime_env, timeout=120, print_output=False).stdout
            if "containers.hybrid_services.host_processes" not in inspected:
                raise RuntimeError("Reference fixture did not assemble opt-in production profile declarations")
        install_reference_silo_fixture(checkout)
        RUNTIME.install_public_origin_fixture(checkout)
    REFERENCE.initialize_reference_fixture_secrets(checkouts, runtime_env)
    REFERENCE.prove_worktree_plans(checkouts, runtime_env)
    for checkout in checkouts:
        prepared = RUNTIME.run([EFFIGY, "--repo", str(checkout), "workspace:js:prepare"],
                               cwd=checkout, env=runtime_env, timeout=900, print_output=False)
        if prepared.returncode:
            raise RuntimeError(f"Reference workspace preparation failed for {checkout}")

    colima_start_attempted = False
    started_colima = False
    safe_to_purge_colima = False
    try:
        colima_start_attempted = True
        RUNTIME.run(["colima", "start", "--profile", "effigy", "--runtime", "containerd",
                     "--cpu", "6", "--memory", "8", "--disk", "64"],
                    env=runtime_env, timeout=1200)
        started_colima = True
        image_receipt = prepare_published_images(fixture_root, runtime_env)
        receipts = verify_profile_runtime(checkouts, runtime_env, storage_only=storage_only)
        receipts["checkout_retire"] = []
        for checkout in checkouts:
            retired = effigy_json(checkout, runtime_env, "container", "retire", "--yes", "--json", timeout=900)
            empty_retirement = (
                retired.get("idempotent") is True
                and retired.get("scope") is None
                and not retired.get("removed")
                and not retired.get("remaining")
            )
            if ((retired.get("record_removed") is not True and not empty_retirement)
                    or retired.get("remaining") or retired.get("unverified_profiles")):
                raise RuntimeError(f"Reference checkout scope retirement is uncertain: {checkout}")
            receipts["checkout_retire"].append({"checkout": str(checkout), "result": retired})
            gateway = RUNTIME.gateway_json(EFFIGY, runtime_env, profile_root(checkout), "status")
            test_gateway = RUNTIME.gateway_json(EFFIGY, runtime_env, profile_root(checkout, "test"), "status")
            if (gateway.get("running") or gateway.get("routes")
                    or test_gateway.get("running") or test_gateway.get("routes")):
                raise RuntimeError(f"Reference checkout retirement left a private gateway route active: {checkout}")
        inventory_envelope = json.loads(RUNTIME.run(
            [EFFIGY, "container", "status", "--global", "--json"],
            env=runtime_env, timeout=120, print_output=False,
        ).stdout)
        inventory = inventory_envelope.get("result") or {}
        if inventory_envelope.get("ok") is not True or inventory.get("environment_count") != 0:
            raise RuntimeError(f"private Colima profile still has active Effigy scopes: {inventory}")
        receipts["global_runtime_after_retirement"] = inventory
        RUNTIME.run([EFFIGY, "container", "profile", "purge", "--profile", "effigy", "--yes", "--json"],
                    env=runtime_env, timeout=600, print_output=False)
        profile_status = json.loads(RUNTIME.run(
            [EFFIGY, "container", "profile", "status", "--profile", "effigy", "--json"],
            env=runtime_env, timeout=120, print_output=False,
        ).stdout).get("result") or {}
        if profile_status.get("exists") is not False:
            raise RuntimeError(f"private Colima profile purge was not verified: {profile_status}")
        receipts["private_profile_purge"] = profile_status
        safe_to_purge_colima = True
        receipts["effigy_source"] = "2f7b1819fd0e72afff18a6053be424719ecf71fc"
        receipts["effigy_binary"] = str(Path(EFFIGY).resolve())
        receipts["effigy_binary_sha256"] = "2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc"
        receipts["silo_images"] = image_receipt
        receipts["reference_source"] = str(source)
        receipt_path = fixture_root / "profile-selector-receipts.json"
        receipt_path.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        print(f"PASS production opt-in Reference profile selectors; receipt: {receipt_path}", flush=True)
        return 0
    finally:
        if colima_start_attempted and not safe_to_purge_colima:
            print("PRIVATE COLIMA PROFILE HELD: profile resources could not be fully reconciled; inspect the retained fixture root before cleanup",
                  file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"OPT-IN REFERENCE PROFILE PROOF FAILED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
