#!/usr/bin/env python3
"""Qualify the private Reference default container stack without host apps."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import traceback
from pathlib import Path

from qualification_runtime import require_effigy_binary


REPO = Path(__file__).resolve().parents[1]
REFERENCE_PATH = REPO / "scripts/qualify-reference-profiles.py"
SPEC = importlib.util.spec_from_file_location("qualify_reference_profiles", REFERENCE_PATH)
REFERENCE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(REFERENCE)
RUNTIME_PATH = REPO / "scripts/qualify-reference-runtime.py"
RUNTIME_SPEC = importlib.util.spec_from_file_location("qualify_reference_runtime", RUNTIME_PATH)
RUNTIME = importlib.util.module_from_spec(RUNTIME_SPEC)
assert RUNTIME_SPEC and RUNTIME_SPEC.loader
RUNTIME_SPEC.loader.exec_module(RUNTIME)


def run(args: list[str], *, env: dict[str, str], cwd: Path | None = None,
        timeout: int = 900, expected: int = 0, output: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                            timeout=timeout, check=False)
    print(f"EXIT: {result.returncode}", flush=True)
    if output:
        if result.stdout.strip():
            print(result.stdout.rstrip(), flush=True)
        if result.stderr.strip():
            print(result.stderr.rstrip(), flush=True)
    else:
        print(f"OUTPUT: captured stdout={len(result.stdout)} bytes stderr={len(result.stderr)} bytes", flush=True)
    if result.returncode != expected:
        detail = RUNTIME.safe_effigy_error(result.stdout) or RUNTIME.safe_effigy_error(result.stderr)
        raise RuntimeError(f"expected exit {expected}, got {result.returncode}: {' '.join(args)}"
                           + (f"; {detail}" if detail else ""))
    return result


def effigy_json(binary: str, checkout: Path, env: dict[str, str], *args: str,
                timeout: int = 180) -> dict:
    result = run([binary, "--repo", str(checkout), *args], cwd=checkout,
                 env=env, timeout=timeout)
    envelope = json.loads(result.stdout)
    if envelope.get("ok") is not True:
        detail = REFERENCE.safe_effigy_error(result.stdout)
        raise RuntimeError(f"Effigy command returned a negative result for {' '.join(args)}"
                           + (f": {detail}" if detail else ""))
    return envelope.get("result") or {}


def gateway_json(binary: str, env: dict[str, str], gateway_root: Path, *args: str) -> dict:
    result = run([binary, "--json", "gateway", *args,
                  "--private-state-root", str(gateway_root)], env=env, timeout=180)
    envelope = json.loads(result.stdout)
    if envelope.get("ok") is not True:
        raise RuntimeError(f"private gateway command returned a negative result: {' '.join(args)}")
    return envelope.get("result") or {}


def services_up(status: dict) -> dict[str, str]:
    return {str(item.get("name")): str(item.get("status"))
            for item in status.get("services", []) if isinstance(item, dict)}


def main() -> int:
    effigy = require_effigy_binary()
    REFERENCE.EFFIGY = effigy
    reference_source = REFERENCE.reference_source()
    fixture_root = RUNTIME.mktemp_root()
    print(f"PRIVATE REFERENCE DEFAULT-CONTAINER ROOT: {fixture_root}", flush=True)
    private_home = fixture_root / "home"
    private_home.mkdir(mode=0o700)
    colima_home = fixture_root / "colima-home"
    colima_home.mkdir(mode=0o700)
    gateway_root = fixture_root / "gateway"
    gateway_root.mkdir(mode=0o700)
    runtime_env = os.environ.copy()
    runtime_env.update({
        "HOME": str(private_home),
        "COLIMA_HOME": str(colima_home),
        "EFFIGY_COMPOSE_BACKEND": "colima",
        "EFFIGY_GATEWAY_PRIVATE_STATE_ROOT": str(gateway_root),
        "UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT": str(fixture_root),
    })
    runtime_env.pop("DOCKER_HOST", None)
    runtime_env.pop("DOCKER_CONTEXT", None)
    receipts: dict[str, object] = {
        "effigy_source": os.environ["UNDERLAY_PROFILE_EFFIGY_SOURCE"],
        "effigy_binary": effigy,
        "reference_source_commit": subprocess.run(
            ["git", "-C", str(reference_source), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip(),
        "fixture_root": str(fixture_root),
        "container_up": None,
        "cleanup": [],
    }
    checkout: Path | None = None
    gateway_attempted = False
    profile_started = False
    stack_attempted = False
    cleanup_verified = False
    failure: str | None = None
    try:
        occupied = RUNTIME.fixed_default_ports_available()
        receipts["default_ports_available"] = occupied == []
        if occupied:
            raise RuntimeError(f"default Reference ports are occupied; startup held safely: {occupied}")

        reference_root = private_home / "reference"
        reference_root.mkdir(mode=0o700)
        checkouts = REFERENCE.make_reference_instances(reference_source, reference_root)
        checkout = checkouts[0]
        for item in checkouts:
            REFERENCE.point_bundle_at_task_branch(item)
        secrets = REFERENCE.initialize_reference_fixture_secrets([checkout], runtime_env)
        receipts["fixture_secrets"] = {
            "vault_count": len(secrets.get("vaults", [])),
            "secret_values_recorded": False,
        }
        assembled = json.loads(run(
            [effigy, "--repo", str(checkout), "bundle", "inspect", "--json"],
            cwd=checkout, env=runtime_env, timeout=120,
        ).stdout)["result"]
        if assembled.get("source", {}).get("source_type") != "path" or Path(
            assembled["source"]["source_path"]
        ).resolve() != REPO.resolve():
            raise RuntimeError("Reference default stack did not assemble this bundle branch")
        plan = run([effigy, "--repo", str(checkout), "dev", "--plan"],
                   cwd=checkout, env=runtime_env, timeout=180)
        config = run([effigy, "--repo", str(checkout), "config", "--inspect"],
                     cwd=checkout, env=runtime_env, timeout=120)
        plan_receipt = {
            "exit": plan.returncode,
            "stdout_sha256": hashlib.sha256(plan.stdout.encode()).hexdigest(),
            "sources_siblings_false": "siblings = false" in (checkout / "effigy.toml").read_text(encoding="utf-8"),
            "default_ports": {str(port): f'"{port}:{port}"' in config.stdout
                              for port in (41001, 41002, 41003)},
            "workspace_image_in_task_plan": "workspace-rust-bun" in plan.stdout,
        }
        if not plan_receipt["sources_siblings_false"] or not all(plan_receipt["default_ports"].values()):
            raise RuntimeError("private Reference default inputs or siblings=false task resolution changed")
        receipts["default_dev_plan"] = plan_receipt

        run([effigy,'--repo',str(checkout),'silo:prepare'],cwd=checkout,env=runtime_env,timeout=60)
        run([effigy,'--repo',str(checkout),'silo:admit'],cwd=checkout,env=runtime_env,timeout=60)
        from formatter_provenance import bind_host, bound_colima, observe, version_arguments
        from reference_storage_probe import StorageDiagnosticJournal
        import sys
        interface_spec=importlib.util.spec_from_file_location('container_image_interfaces',REPO/'scripts/qualify-storage-correlation.py')
        interfaces=importlib.util.module_from_spec(interface_spec);sys.modules[interface_spec.name]=interfaces;interface_spec.loader.exec_module(interfaces)
        packet=Path(subprocess.run(['mktemp','-d',str(Path.home()/'ur.005-container.XXXXXX')],check=True,capture_output=True,text=True).stdout.strip())
        journal=StorageDiagnosticJournal(packet/'storage-diagnostics.jsonl',fixture_root)
        bind_host(runtime_env)
        version_arguments(runtime_env,fixture_root)
        gateway_attempted = True
        gateway_json(effigy, runtime_env, gateway_root, "setup-tls")
        gateway_status = gateway_json(
            effigy, runtime_env, gateway_root, "up",
            "--dns-addr", "127.0.0.1:0", "--proxy-addr", "127.0.0.1:0",
            "--https-addr", "127.0.0.1:0",
        )
        if gateway_status.get("private") is not True or gateway_status.get("running") is not True:
            raise RuntimeError("the disposable private gateway did not report running")
        receipts["private_gateway"] = {
            "https_addr": gateway_status.get("https_addr"),
            "ca_installed": (gateway_status.get("tls") or {}).get("ca_installed"),
        }

        run([bound_colima(runtime_env), "start", "--profile", "effigy", "--runtime", "containerd",
             "--cpu", "6", "--memory", "8", "--disk", "64"], env=runtime_env, timeout=1200, output=True)
        profile_started = True

        receipts['formatter']=observe(runtime_env,fixture_root,journal)
        from silo_fixture import prepare_published_images, IMAGE, CLIENT_IMAGE
        prepare_published_images(fixture_root,runtime_env,client_probe=lambda shape:interfaces.client_image_provenance(runtime_env,journal,shape))
        interfaces.image_interfaces(runtime_env,journal,__import__('secrets').token_hex(16))
        stack_attempted = True
        up = effigy_json(effigy, checkout, runtime_env, "container", "up", "--detach", "--json", timeout=5400)
        status = effigy_json(effigy, checkout, runtime_env, "container", "status", "--json", timeout=180)
        effective = services_up(status)
        if not effective or any(value.lower() != "up" for value in effective.values()):
            raise RuntimeError(f"default Reference container stack did not reach all-Up state: {effective}")
        compose_path = Path(status["compose_file"])
        if not compose_path.is_absolute():
            compose_path = checkout / compose_path
        receipts["container_up"] = {
            "exit": 0,
            "result_schema": up.get("schema"),
            "services": effective,
            "compose_file": str(compose_path),
            "storage_product": "PGSTY Silo",
        }
        compose = compose_path.read_text(encoding="utf-8")
        workspace_service = re.search(
            r"(?ms)^  workspace:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", compose
        )
        dockerfile_match = re.search(
            r"(?m)^      dockerfile: (.+)$", workspace_service.group(1)
        ) if workspace_service else None
        dockerfile_candidate = checkout / dockerfile_match.group(1) if dockerfile_match else None
        workspace_dockerfile = dockerfile_candidate.resolve() if dockerfile_candidate else None
        dockerfile_text = workspace_dockerfile.read_text(encoding="utf-8") if (
            workspace_dockerfile and workspace_dockerfile.is_file()
        ) else ""
        export_text = (REPO / "export.toml").read_text(encoding="utf-8")
        receipts["container_up"].update({
            "compose_sha256": hashlib.sha256(compose.encode()).hexdigest(),
            "workspace_service_present": workspace_service is not None,
            "workspace_service_has_build": bool(workspace_service and "build:" in workspace_service.group(1)),
            "workspace_rust_bun_catalog_mapping": 'catalog = "workspace-rust-bun"' in export_text,
            "workspace_dockerfile": str(workspace_dockerfile) if workspace_dockerfile else None,
            "workspace_dockerfile_sha256": hashlib.sha256(dockerfile_text.encode()).hexdigest()
                if dockerfile_text else None,
            "workspace_toolchain_markers": {
                marker: marker in dockerfile_text for marker in ("FROM rust:", "ARG BUN_VERSION", "BUN_INSTALL")
            },
            "silo_server_pin": IMAGE in compose,
            "silo_client_pin": CLIENT_IMAGE in compose,
            "obsolete_storage_service": bool(re.search(r"(?m)^  minio:",compose)),
        })
        if not receipts["container_up"]["workspace_service_has_build"]:
            raise RuntimeError("default stack did not generate a built workspace service")
        if not dockerfile_match or not workspace_dockerfile:
            raise RuntimeError("default workspace service omitted its catalog Dockerfile")
        if checkout.resolve() not in workspace_dockerfile.parents:
            raise RuntimeError("generated workspace Dockerfile escaped the private Reference checkout")
        if not all(receipts["container_up"]["workspace_toolchain_markers"].values()):
            raise RuntimeError("generated default workspace image is missing its pinned Rust/Bun toolchain")
        if not receipts["container_up"]["workspace_rust_bun_catalog_mapping"]:
            raise RuntimeError("bundle default no longer maps the workspace service to workspace-rust-bun")
        if not receipts['container_up']['silo_server_pin'] or not receipts['container_up']['silo_client_pin'] or receipts['container_up']['obsolete_storage_service']:
            raise RuntimeError('default stack storage identity refused')
        run([effigy,'--repo',str(checkout),'silo:reconcile'],cwd=checkout,env=runtime_env,timeout=180)
        print('PASS private Reference default container build/startup and production Silo bootstrap',flush=True)
    except Exception as error:
        failure = f"{type(error).__name__}: {error}"
        print(f"REFERENCE DEFAULT-CONTAINER QUALIFICATION BLOCKED: {failure}", flush=True)
    finally:
        if checkout is not None and stack_attempted:
            try:
                down = effigy_json(effigy, checkout, runtime_env, "container", "down", "--json", timeout=600)
                status = effigy_json(effigy, checkout, runtime_env, "container", "status", "--json", timeout=180)
                active = [name for name, value in services_up(status).items() if value.lower() == "up"]
                receipts["cleanup"].append({
                    "container_down": down,
                    "services_up_after_down": active,
                    "retirement_proven": False,
                    "retirement_verified": False,
                })
                if active:
                    raise RuntimeError("private default container stack scoped shutdown is uncertain")
            except Exception as error:
                receipts["cleanup"].append({"container_cleanup_error": f"{type(error).__name__}: {error}"})
        cleanup_verified = bool(checkout is not None and stack_attempted and not any(
            item.get('container_cleanup_error') for item in receipts['cleanup']))
        if profile_started and checkout is not None:
            try:
                inventory_result = json.loads(run(
                    [effigy, "container", "status", "--global", "--json"],
                    env=runtime_env, timeout=120,
                ).stdout)
                inventory = inventory_result.get("result") or {}
                count = inventory.get("environment_count")
                receipts["cleanup"].append({"global_runtime_environment_count": count})
                if inventory_result.get("ok") is not True or count != 0:
                    cleanup_verified = False
            except Exception as error:
                receipts["cleanup"].append({"global_runtime_inventory_error": type(error).__name__})
                cleanup_verified = False
        if gateway_attempted:
            try:
                gateway = gateway_json(effigy, runtime_env, gateway_root, "status")
                route_count = len(gateway.get("routes", []))
                receipts["cleanup"].append({"private_gateway_routes_before_down": route_count})
                if route_count:
                    cleanup_verified = False
                if cleanup_verified:
                    receipts["cleanup"].append({"gateway_down": gateway_json(
                        effigy, runtime_env, gateway_root, "down",
                    )})
            except Exception as error:
                receipts["cleanup"].append({"private_gateway_cleanup_error": type(error).__name__})
                cleanup_verified = False
        if profile_started:
            receipts["resource_disposition"]={"vm_images_volumes":"held", "retirement_proven":False}

        receipts["cleanup_verified"] = cleanup_verified
        if failure:
            receipts["failure"] = failure
        receipt_path = fixture_root / "default-container-receipts.json"
        receipt_path.write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        print(f"REFERENCE DEFAULT-CONTAINER RECEIPTS: {receipt_path}", flush=True)

    if failure or not receipts.get("container_up") or not cleanup_verified:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
