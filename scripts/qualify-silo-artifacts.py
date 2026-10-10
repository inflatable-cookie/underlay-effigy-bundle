#!/usr/bin/env python3
"""Verify the approved published Silo and MC metadata without a runtime."""
import json
import hashlib
import urllib.request
import tempfile
from pathlib import Path
from qualification_runtime import require_effigy_binary
from silo_fixture import registry_contract

require_effigy_binary()
root = Path(tempfile.mkdtemp(prefix="underlay-silo-artifacts-"))
receipts = {f"{repository}/{arch}": registry_contract(repository, arch)
            for repository in ("pgsty/silo", "pgsty/mc") for arch in ("arm64", "amd64")}
# Release assets are separate from OCI attestations. Inventory the exact tag,
# and hash the published Linux server SBOMs; do not claim signature verification.
for repository in ("pgsty/silo", "pgsty/mc"):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/releases/tags/RELEASE.2026-09-16T00-00-00Z",
        headers={"User-Agent": "underlay-reference-qualification"})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    if release["tag_name"] != "RELEASE.2026-09-16T00-00-00Z" or release.get("draft"):
        raise RuntimeError("published release differs from approved tag")
    assurance = [asset for asset in release["assets"] if any(
        name in asset["name"].lower() for name in ("sbom", "spdx", "sigstore", "provenance", "attestation"))]
    receipts[f"{repository}/release_assurance"] = {
        "url": release["html_url"], "published_at": release["published_at"],
        "assets": [{key: asset.get(key) for key in ("name", "digest", "browser_download_url")} for asset in assurance],
        "signature_verified": False}
    for arch in ("arm64", "amd64"):
        expected = f"silo_20260916000000.0.0_linux_{arch}.tar.gz.sbom.json"
        matching = [asset for asset in assurance if asset["name"] == expected]
        if repository != "pgsty/silo":
            continue
        if len(matching) != 1:
            raise RuntimeError("published Silo release lacks its Linux platform SBOM")
        asset = matching[0]
        url = asset["browser_download_url"]
        if url != f"https://github.com/pgsty/silo/releases/download/RELEASE.2026-09-16T00-00-00Z/{expected}":
            raise RuntimeError("SBOM URL differs from exact published release asset")
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if len(raw) > 8 * 1024 * 1024 or digest != asset.get("digest"):
            raise RuntimeError("published SBOM failed content digest verification")
        sbom = json.loads(raw)
        files = [item for item in sbom["files"] if item["fileName"] == "silo"]
        hashes = [checksum["checksumValue"] for item in files for checksum in item.get("checksums", [])
                  if checksum["algorithm"] == "SHA256"]
        if len(hashes) != 1 or sbom.get("spdxVersion") != "SPDX-2.3":
            raise RuntimeError("published SBOM does not identify one Silo executable")
        # This arm64 executable hash was observed from the approved private
        # container image, not inferred from a source checkout or website main.
        if arch == "arm64" and hashes[0] != "f11e1f8765ed92801a0b24ce00c1b97ca2a01eb2f0b99fcf11ecbf244575fa55":
            raise RuntimeError("published arm64 SBOM differs from the observed Silo image executable")
        receipts[f"{repository}/{arch}"]["release_sbom"] = {
            "url": url, "digest": digest, "format": "SPDX-2.3", "package_count": len(sbom["packages"]),
            "executable_sha256": hashes[0], "matches_observed_private_executable": arch == "arm64",
            "signature_verified": False}
path = root / "registry-contracts.json"
path.write_text(json.dumps(receipts, indent=2) + "\n")
path.chmod(0o600)
print(f"PASS digest/platform/config/source provenance contracts; unsigned metadata, not signature assurance: {path}")
