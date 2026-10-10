"""Published PGSTY Silo/MC inputs for disposable Reference qualification.

Registry receipts verify content and available provenance, not a publisher
signature. Only the task-private Colima profile receives these images.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
from pathlib import Path

import subprocess

RELEASE = "RELEASE.2026-09-16T00-00-00Z"
SERVER_DIGEST = "sha256:635197cb9f36d01bee221d34d1c7d7960f6a95c48b0b6c01d99cd13bdae51a46"
CLIENT_DIGEST = "sha256:cfc83108c3abb371f8fb84d99c1fdc88f8c237e022409b0081fb7c0a3be634dd"
IMAGE = f"docker.io/pgsty/silo:{RELEASE}@{SERVER_DIGEST}"
CLIENT_IMAGE = f"docker.io/pgsty/mc:{RELEASE}@{CLIENT_DIGEST}"
PINS = {
    "pgsty/silo": {"digest": SERVER_DIGEST, "revision": "2a4d51406b7ed87af5fe6fe0f801f3290f96eb3c",
                   "entrypoint": ["/usr/bin/docker-entrypoint.sh"],
                   "arm64": "sha256:1ff329e4507f742a8437f1773d43cf6adb0131477074dd45c770d1a1db19e99c",
                   "amd64": "sha256:39aab3c365848e32aca7b76c5b57f86d1cbca02d7b8f24e1fd1feff9fedddae5"},
    "pgsty/mc": {"digest": CLIENT_DIGEST, "revision": "e952aa78f10a2b77dd525a2b7e3143bcda0cd377",
                 "entrypoint": ["/usr/bin/mc"],
                 "arm64": "sha256:c44abbbd8f1b31ecfcc3aa71c210645a104c4f6f515baf85be37ab7ca4fb520d",
                 "amd64": "sha256:8ac3333f012adb27c406df77c7cae6ce700892cc44ee489036404e3fc356e9ea"},
}


def command(args: list[str], *, env: dict[str, str], cwd: Path | None = None, timeout: int = 3600) -> str:
    print(f"COMMAND: {' '.join(args)}", flush=True)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    print(f"EXIT: {result.returncode}", flush=True)
    if result.stdout.strip():
        print(result.stdout.rstrip(), flush=True)
    if result.stderr.strip():
        print(result.stderr.rstrip(), flush=True)
    if result.returncode:
        # Preserve enough bounded build context for a private fixture failure
        # receipt to identify the failing stage without dumping an unbounded
        # compiler log or any task environment values.
        stderr = result.stderr.rstrip()[-3600:]
        stdout = result.stdout.rstrip()[-1200:]
        excerpt = "\n".join(part for part in (stderr, stdout) if part)
        raise RuntimeError(
            f"command exited {result.returncode}: {' '.join(args)}"
            + (f"\nbounded command output tail:\n{excerpt}" if excerpt else "")
        )
    return result.stdout


def registry_contract(repository: str, arch: str) -> dict:
    """Hash all metadata and retain only bounded public artifact facts."""
    pin = PINS[repository]
    url = "https://auth.docker.io/token?" + urllib.parse.urlencode({
        "service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
    with urllib.request.urlopen(url, timeout=30) as response:
        token = json.load(response)["token"]

    def fetch(kind: str, digest: str) -> dict:
        request = urllib.request.Request(f"https://registry-1.docker.io/v2/{repository}/{kind}/{digest}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024 or "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise RuntimeError(f"registry {repository} {kind} content failed bounded digest verification")
        return json.loads(body)

    index = fetch("manifests", pin["digest"])
    selected = [item for item in index.get("manifests", [])
                if item.get("platform", {}).get("os") == "linux" and item.get("platform", {}).get("architecture") == arch]
    if len(selected) != 1 or selected[0]["digest"] != pin[arch]:
        raise RuntimeError(f"{repository} linux/{arch} child differs from approved receipt")
    child = fetch("manifests", selected[0]["digest"])
    config = fetch("blobs", child["config"]["digest"])
    settings = config["config"]
    labels = settings.get("Labels", {})
    for key, value in {"source": f"https://github.com/{repository}", "revision": pin["revision"], "version": RELEASE}.items():
        if labels.get(f"org.opencontainers.image.{key}") != value:
            raise RuntimeError(f"{repository} OCI {key} differs from selected release")
    if config.get("os") != "linux" or config.get("architecture") != arch or settings.get("Entrypoint") != pin["entrypoint"]:
        raise RuntimeError(f"{repository} platform or entrypoint differs from selected artifact")
    attestations = []
    provenance_found = False
    for descriptor in index.get("manifests", []):
        annotations = descriptor.get("annotations", {})
        if annotations.get("vnd.docker.reference.digest") != selected[0]["digest"]:
            continue
        attestation = fetch("manifests", descriptor["digest"])
        for layer in attestation.get("layers", []):
            statement = fetch("blobs", layer["digest"])
            if not any(item.get("digest", {}).get("sha256") == selected[0]["digest"].split(":")[1]
                       for item in statement.get("subject", [])):
                raise RuntimeError(f"{repository} attestation subject does not match selected child")
            predicate_type = statement.get("predicateType", "")
            if "slsa.dev/provenance" in predicate_type:
                # BuildKit records vcs inputs in externalParameters; verify the
                # exact source/revision without persisting its build environment.
                external = statement.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {})
                serialized = json.dumps(external, sort_keys=True)
                if pin["revision"] not in serialized or f"https://github.com/{repository}" not in serialized:
                    raise RuntimeError(f"{repository} provenance source/revision differs from OCI labels")
                provenance_found = True
            attestations.append({"digest": layer["digest"], "predicate_type": predicate_type})
    if not provenance_found:
        raise RuntimeError(f"{repository} lacks matching published source provenance")
    return {"repository": repository, "release": RELEASE, "source": f"https://github.com/{repository}",
            "revision": pin["revision"], "index_digest": pin["digest"], "child_digest": selected[0]["digest"],
            "config_digest": child["config"]["digest"], "platform": f"linux/{arch}",
            "entrypoint": settings.get("Entrypoint"), "command": settings.get("Cmd"),
            "attestations": attestations, "signature_verified": False,
            "sbom_available": any("spdx" in item["predicate_type"].lower() or "cyclonedx" in item["predicate_type"].lower() for item in attestations)}


def prepare_published_images(runtime_root: Path, environment: dict[str, str]) -> dict:
    colima_home = Path(environment["COLIMA_HOME"]).resolve(strict=True)
    if runtime_root.resolve() not in colima_home.parents:
        raise RuntimeError("Silo qualification requires task-private COLIMA_HOME")
    guest = command(["colima", "ssh", "--profile", "effigy", "--", "uname", "-m"], env=environment, timeout=60).strip()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(guest)
    if arch is None:
        raise RuntimeError("unsupported private guest architecture")
    result = {"product": "PGSTY Silo (downstream fork)", "image": IMAGE, "client_image": CLIENT_IMAGE,
              "server": registry_contract("pgsty/silo", arch), "client": registry_contract("pgsty/mc", arch)}
    receipt = runtime_root / "silo-published-images.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    receipt.chmod(0o600)
    for image in (IMAGE, CLIENT_IMAGE):
        command(["colima", "nerdctl", "--profile", "effigy", "--", "pull", "--platform", f"linux/{arch}", image], env=environment, timeout=1200)
    prefix = ["colima", "nerdctl", "--profile", "effigy", "--", "run", "--rm"]
    shape = command(prefix + ["--entrypoint", "/bin/sh", IMAGE, "-c",
        "command -v silo; command -v mc; command -v mcli; silo --version; mc --version; sha256sum /usr/bin/silo /usr/bin/mc"], env=environment, timeout=60)
    client_version = command(prefix + [CLIENT_IMAGE, "--version"], env=environment, timeout=60)
    if RELEASE not in shape or RELEASE not in client_version:
        raise RuntimeError("published Silo/client executable release differs from selected image")
    if PINS["pgsty/silo"]["revision"][:12] not in shape or PINS["pgsty/mc"]["revision"][:12] not in client_version:
        raise RuntimeError("published Silo/client executable commit differs from source provenance")
    result["executable_shape"] = shape.strip()
    result["client_version"] = client_version.strip()
    receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"PASS published Silo platform/release contract; receipt: {receipt}", flush=True)
    return result


def install_minio_catalog_override(effigy: str, checkout: Path, env: dict[str, str],
                                  cors_origin: str) -> str:
    """Use Effigy's documented project-local catalog override in a fixture."""
    command(
        [effigy, "--repo", str(checkout), "service", "extract", "minio", "--dir", "infra/dev/catalog", "--json"],
        env=env,
        timeout=60,
    )
    fragment = checkout / "infra/dev/catalog/minio/compose.fragment.yml"
    raw = fragment.read_text(encoding="utf-8")
    baseline = raw
    original = "image: minio/minio:{{ version }}"
    if original not in raw:
        raise RuntimeError("extracted MinIO catalog fragment differs from the pinned source baseline")
    raw = raw.replace(original, f"image: {IMAGE}")
    for before, after in (
        ('"{{ api_port }}:9000"', '"0:9000"'),
        ('"{{ console_port }}:9001"', '"0:9001"'),
    ):
        if before not in raw:
            raise RuntimeError(f"MinIO fixture catalog fragment lacks expected port mapping {before}")
        raw = raw.replace(before, after)
    marker = 'MINIO_ROOT_PASSWORD: "{{ root_password }}"'
    if marker not in raw:
        raise RuntimeError("MinIO fixture catalog fragment lacks the baseline root-password mapping")
    raw = raw.replace(
        marker,
        marker
        + "\n      MINIO_API_CORS_ALLOW_ORIGIN: " + json.dumps(cors_origin)
        + '\n      MC_HOST_local: "http://{{ root_user }}:{{ root_password }}@127.0.0.1:9000"',
    )
    fragment.write_text(raw, encoding="utf-8")
    print(
        f"FIXTURE ONLY: {checkout}/infra/dev/catalog/minio uses the published Silo image {IMAGE} and server CORS origin {cors_origin}; published default remains untouched",
        flush=True,
    )
    return baseline
