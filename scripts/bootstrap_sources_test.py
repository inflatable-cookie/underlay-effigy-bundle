#!/usr/bin/env python3.11
"""Render and plan regression for the bootstrap setup and pinned sources.

Each scenario writes a nonsecret consumer fixture into a fresh mktemp root,
points `[bundle].base` at this checkout, and reads Effigy's own surfaces:
`config --inspect` (effective manifest) and `bootstrap --plan`. Nothing is
fetched, acquired, installed or started. The one execution is `deps:prepare`
in a fixture with no package manifests: it proves the rhai helper compiles and
dispatches, and it has nothing to install.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
EFFIGY = os.environ.get("EFFIGY_BIN", "effigy")

UNDERLAY_PIN = "54975f3d87684c84ad1e9b99ec9577db4df7c675"
POODLE_PIN = "3fff871e6b21a0abdd08f766cd02a440d8871f91"
LONGHORN_PIN = "64371e89b3f243cc00b40723b09427058de24b3a"
OTHER_PIN = "1111111111111111111111111111111111111111"

DEFAULT_SETUP = ["secrets init", "container up --detach", "minio:reconcile", "deps:prepare"]
JS_ROOT_SETUP = ["secrets init", "container up --detach", "minio:reconcile", "workspace:js:prepare"]
NO_DEPS_SETUP = ["secrets init", "container up --detach", "minio:reconcile"]
RETIRED = ("bootstrap.children", "deps sync", "db-seed", "submodules")
DEFAULT_DIRS = {"api": "app-api", "client": "app-client", "admin": "app-admin", "front": "app-front"}
ROLES = ("api", "client", "admin", "front", "ui", "docs")
BASE_INPUTS: dict[str, object] = {
    "host": "fixture.test",
    "workspace_subdir": "fixture",
    "databases": ["fixture"],
}


def toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


def bundle_block(inputs: dict[str, object], bundle: Path) -> str:
    """Render `[bundle]` with dotted input keys as nested sub-tables."""
    lines = ["[bundle]", f'base = {{ type = "path", dir = {json.dumps(str(bundle))} }}']
    nested: dict[str, dict[str, object]] = {}
    for key, value in inputs.items():
        if "." in key:
            table, field = key.split(".", 1)
            nested.setdefault(table, {})[field] = value
        else:
            lines.append(f"{key} = {toml_value(value)}")
    for table, fields in nested.items():
        lines.append("")
        lines.append(f"[bundle.{table}]")
        lines.extend(f"{field} = {toml_value(value)}" for field, value in fields.items())
    return "\n".join(lines) + "\n"


def run_effigy(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([EFFIGY, *args], cwd=cwd, capture_output=True, text=True, timeout=180, check=False)


def envelope(args: list[str], cwd: Path) -> dict:
    proc = run_effigy(["--json", *args], cwd)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"`effigy --json {' '.join(args)}` printed no JSON: {error}\n{proc.stderr}") from error
    payload["_exit"] = proc.returncode
    return payload


class Fixture:
    """One nonsecret consumer checkout with its member and sibling directories."""

    def __init__(self, root: Path, inputs: dict[str, object] | None = None, extra_toml: str = "",
                 bundle: Path = BUNDLE):
        self.root = root
        self.consumer = root / "consumer"
        self.consumer.mkdir()
        merged = dict(BASE_INPUTS)
        merged.update(inputs or {})
        self.inputs = merged
        for role in ROLES:
            path = merged.get(f"dirs.{role}") or DEFAULT_DIRS.get(role)
            if path:
                self.member(str(path), str(merged.get(f"catalogs.{role}") or path))
        self.member(str(merged.get("sources.underlay", "../underlay")), "underlay")
        self.member(str(merged.get("sources.poodle", "../poodle")), "poodle")
        (self.consumer / "effigy.toml").write_text(
            "[catalog]\nalias = \"fixture\"\n\n" + bundle_block(merged, bundle) + "\n" + extra_toml,
            encoding="utf-8",
        )

    def member(self, relative: str, alias: str) -> None:
        target = (self.consumer / relative).resolve()
        if not str(target).startswith(str(self.root.resolve())):
            raise AssertionError(f"fixture path escapes its mktemp root: {target}")
        target.mkdir(parents=True, exist_ok=True)
        (target / "effigy.toml").write_text(f"[catalog]\nalias = \"{alias}\"\n", encoding="utf-8")

    def effective(self) -> dict:
        payload = envelope(["--repo", str(self.consumer), "config", "--inspect"], self.consumer)
        if payload["_exit"] != 0 or not payload.get("ok"):
            raise AssertionError(f"config --inspect refused: {payload.get('error')}")
        return tomllib.loads(payload["result"]["effective_manifest"])

    def plan(self) -> dict:
        payload = envelope(["bootstrap", "--plan"], self.consumer)
        if payload["_exit"] != 0 or not payload.get("ok"):
            raise AssertionError(f"bootstrap --plan failed: {payload.get('error')}")
        return payload["result"]


class BootstrapSourcesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bundle-fixture-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.count = 0

    def fixture(self, **kwargs) -> Fixture:
        self.count += 1
        root = self.tmp / f"case-{self.count}"
        root.mkdir()
        return Fixture(root, **kwargs)

    def assert_no_retired(self, effective: dict) -> None:
        self.assertEqual(set(effective.get("bootstrap", {})) - {"setup", "start"}, set(), "retired bootstrap keys")
        text = json.dumps(effective)
        for word in RETIRED:
            self.assertNotIn(word, text, f"retired surface `{word}` in effective manifest")

    def assert_plan(self, fx: Fixture, setup: list[str]) -> dict:
        plan = fx.plan()
        self.assertIsNone(plan.get("manifest_unreadable"), plan.get("manifest_unreadable"))
        self.assertEqual(plan["plan"]["setup"], setup)
        self.assertEqual(plan["plan"]["start"], "dev")
        return plan

    def source(self, effective: dict, name: str) -> dict:
        self.assertIn(name, effective.get("sources", {}), f"[sources.{name}] missing")
        return effective["sources"][name]

    # 1. Default sibling-enabled flat layout.
    def test_default_siblings_pin_and_order(self) -> None:
        fx = self.fixture()
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], DEFAULT_SETUP)
        self.assertEqual(eff["bootstrap"]["start"], "dev")
        self.assertEqual(self.source(eff, "underlay"), {
            "git": "git@github.com:inflatable-cookie/underlay.git",
            "rev": UNDERLAY_PIN,
            "path": "../underlay",
        })
        self.assertEqual(self.source(eff, "poodle")["rev"], POODLE_PIN)
        self.assertEqual(self.source(eff, "poodle")["path"], "../poodle")
        self.assertIn("deps:prepare", eff["tasks"])
        self.assert_no_retired(eff)
        plan = self.assert_plan(fx, DEFAULT_SETUP)
        self.assertEqual(sorted((s["name"], s["rev"]) for s in plan["plan"]["sources"]),
                         [("poodle", POODLE_PIN), ("underlay", UNDERLAY_PIN)])

    # 2. Explicit consumer setup replaces the bundle list; start is inherited.
    def test_consumer_setup_replaces_and_inherits_start(self) -> None:
        extra = (
            "\n[bootstrap]\nsetup = [\"secrets init\", \"bootstrap:state\"]\n\n"
            "[sources.longhorn]\ngit = \"git@github.com:inflatable-cookie/longhorn.git\"\n"
            f"rev = \"{LONGHORN_PIN}\"\npath = \"../longhorn\"\n\n"
            "[tasks.\"bootstrap:state\"]\nrun = \"true\"\nrun_in = \"host\"\n"
        )
        fx = self.fixture(extra_toml=extra)
        (fx.root / "longhorn").mkdir()
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], ["secrets init", "bootstrap:state"])
        self.assertEqual(eff["bootstrap"]["start"], "dev")
        self.assertEqual(self.source(eff, "longhorn")["rev"], LONGHORN_PIN)
        self.assertEqual(self.source(eff, "underlay")["rev"], UNDERLAY_PIN)
        self.assert_no_retired(eff)
        plan = self.assert_plan(fx, ["secrets init", "bootstrap:state"])
        self.assertEqual(len(plan["plan"]["setup"]), 2)

    # 3a. siblings=false, flat: no sibling source, catalog member or helper step.
    def test_siblings_off_flat_emits_no_sibling_surface(self) -> None:
        fx = self.fixture(inputs={"sources.siblings": False})
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], NO_DEPS_SETUP)
        self.assertNotIn("sources", eff)
        self.assertNotIn("deps:prepare", eff["tasks"])
        self.assertNotIn("underlay", eff["catalog"]["members"])
        self.assertNotIn("poodle", eff["catalog"]["members"])
        self.assert_no_retired(eff)
        self.assertEqual(self.assert_plan(fx, NO_DEPS_SETUP)["plan"]["sources"], [])

    # 3b. Underlay Reference shape: js_root with siblings=false.
    def test_underlay_reference_shape(self) -> None:
        fx = self.fixture(inputs={
            "sources.siblings": False, "workspace.js_root": True,
            "profiles.enabled": True, "profiles.dev": "hybrid",
            "host": "acme.test", "workspace_subdir": "underlay-reference", "databases": ["acme"],
            "dirs.api": "apps/acme-api", "dirs.client": "packages/acme-client",
            "dirs.ui": "packages/acme-ui", "dirs.front": "apps/acme-front",
            "dirs.admin": "apps/acme-admin", "dirs.docs": "docs",
            "catalogs.api": "acme-api", "catalogs.client": "acme-client", "catalogs.ui": "acme-ui",
            "catalogs.front": "acme-front", "catalogs.admin": "acme-admin", "catalogs.docs": "acme-docs",
        })
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], JS_ROOT_SETUP)
        self.assertNotIn("sources", eff)
        self.assertIn("workspace:js:prepare", eff["tasks"])
        self.assertNotIn("deps:prepare", eff["tasks"])
        self.assertEqual(eff["catalog"]["members"]["api"], "apps/acme-api")
        self.assert_no_retired(eff)
        self.assert_plan(fx, JS_ROOT_SETUP)

    # 4. Representative root/child shapes. Physical dirs and catalog aliases split.
    def test_acowtancy_shape(self) -> None:
        fx = self.fixture(inputs={
            "host": "acowtancy.test", "workspace_subdir": "acowtancy",
            "databases": ["acowtancy", "acowtancy_test"],
            "profiles.enabled": True, "profiles.dev": "hybrid",
            "profiles.test_task": "farmyard/host:test:managed",
            "profiles.api_task": "farmyard/api:host", "profiles.jobs_task": "farmyard/jobs:host",
            "profiles.api_health_path": "/health/live",
            "dirs.api": "apps/farmyard", "dirs.front": "apps/cream", "dirs.admin": "apps/dairy",
            "dirs.ui": "packages/froyo", "dirs.client": "packages/cattle-grid",
            "routes.api": "farmyard", "routes.admin": "dairy",
        })
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], DEFAULT_SETUP)
        self.assertEqual(eff["catalog"]["members"]["api"], "apps/farmyard")
        self.assertEqual(eff["catalog"]["members"]["ui"], "packages/froyo")
        self.assert_no_retired(eff)
        self.assert_plan(fx, DEFAULT_SETUP)

    def test_compli_me_shape_physical_and_catalog_paths_split(self) -> None:
        fx = self.fixture(inputs={
            "host": "compli-me.test", "workspace_subdir": "compli-me", "databases": ["compli_me"],
            "workspace.js_root": True, "profiles.enabled": True, "profiles.dev": "hybrid",
            "profiles.test_task": "api/test",
            "dirs.api": "apps/api", "dirs.client": "packages/api-client", "dirs.ui": "packages/ui",
            "dirs.front": "apps/front", "dirs.admin": "apps/admin", "dirs.docs": "docs",
            "catalogs.api": "api", "catalogs.client": "api-client", "catalogs.ui": "ui",
            "catalogs.front": "front", "catalogs.admin": "admin", "catalogs.docs": "docs",
        })
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], JS_ROOT_SETUP)
        self.assertEqual(eff["catalog"]["members"]["admin"], "apps/admin")
        self.assertEqual(eff["tasks"]["health"]["run"][0]["task"], "docs/health")
        self.assertEqual(eff["tasks"]["health"]["run"][1]["task"], "api/health")
        self.assertIn("underlay", eff["catalog"]["members"])
        self.assert_no_retired(eff)
        self.assert_plan(fx, JS_ROOT_SETUP)

    def test_songsprout_shape(self) -> None:
        fx = self.fixture(inputs={
            "host": "songsprout.test", "workspace_subdir": "songsprout", "databases": ["songsprout"],
            "workspace.js_root": True, "profiles.enabled": True, "profiles.dev": "hybrid",
            "profiles.test_task": "nursery/test", "profiles.api_health_path": "/health",
            "profiles.front_health_path": "/login", "profiles.admin_health_path": "/login",
            "dirs.api": "apps/nursery", "dirs.client": "packages/stem", "dirs.ui": "packages/petal",
            "dirs.front": "apps/bloom", "dirs.admin": "apps/greenhouse", "dirs.docs": "docs",
            "catalogs.api": "nursery", "catalogs.client": "stem", "catalogs.ui": "petal",
            "catalogs.front": "bloom", "catalogs.admin": "greenhouse", "catalogs.docs": "trellis",
        })
        eff = fx.effective()
        self.assertEqual(eff["bootstrap"]["setup"], JS_ROOT_SETUP)
        self.assertEqual(eff["catalog"]["members"]["api"], "apps/nursery")
        self.assertEqual(eff["tasks"]["health"]["run"][0]["task"], "trellis/health")
        self.assertEqual(eff["tasks"]["health"]["run"][1]["task"], "nursery/health")
        self.assert_no_retired(eff)
        self.assert_plan(fx, JS_ROOT_SETUP)

    # 5. Consumer pin and path overrides win; the bundle default does not.
    def test_pin_and_path_override(self) -> None:
        fx = self.fixture(inputs={"sources.underlay_rev": OTHER_PIN, "sources.poodle": "vendor/poodle"})
        eff = fx.effective()
        self.assertEqual(self.source(eff, "underlay")["rev"], OTHER_PIN)
        self.assertEqual(self.source(eff, "poodle")["path"], "vendor/poodle")
        self.assertEqual(self.source(eff, "poodle")["rev"], POODLE_PIN)
        plan = self.assert_plan(fx, DEFAULT_SETUP)
        states = {s["name"]: s for s in plan["plan"]["sources"]}
        self.assertEqual(states["underlay"]["rev"], OTHER_PIN)
        self.assertTrue(states["poodle"]["path"].endswith("vendor/poodle"))

    # 6. A missing pin refuses at parse; the plan reports the refusal instead of an empty success.
    def test_missing_pin_refuses(self) -> None:
        fx = self.fixture(inputs={"sources.poodle_rev": ""})
        payload = envelope(["--repo", str(fx.consumer), "config", "--inspect"], fx.consumer)
        self.assertNotEqual(payload["_exit"], 0)
        self.assertIn("rev", payload["error"]["message"])
        plan = envelope(["bootstrap", "--plan"], fx.consumer)["result"]
        self.assertIn("rev", plan["manifest_unreadable"])
        self.assertEqual(plan["plan"]["setup"], [])

    # 7. Setup selectors resolve to built-ins or ordinary tasks.
    def test_setup_selectors_resolve(self) -> None:
        eff = self.fixture().effective()
        for selector in DEFAULT_SETUP:
            if selector not in ("secrets init", "container up --detach"):
                self.assertIn(selector, eff["tasks"], f"setup selector `{selector}` has no task")
        self.assertIn("bootstrap-minio.rhai", json.dumps(eff["tasks"]["minio:reconcile"]))
        self.assertIn("ui-setup.rhai", json.dumps(eff["tasks"]["deps:prepare"]))

    # 8. The bundle raises its floor to v0.15.0. A released v0.14.x binary must
    # refuse the bundle. A +local development build satisfies floors by design,
    # so it cannot exercise the refusal; EFFIGY_V014_BIN names a released binary.
    def test_version_floor_is_declared_and_v014_refuses(self) -> None:
        export = (BUNDLE / "export.toml").read_text(encoding="utf-8")
        self.assertIn('minimum_effigy_version = "0.15.0"', export)
        self.assertIn('extend = ["secrets"]', export)
        legacy = os.environ.get("EFFIGY_V014_BIN")
        if not legacy:
            self.skipTest("set EFFIGY_V014_BIN to a released v0.14.x effigy to prove the refusal")
        fx = self.fixture()
        proc = subprocess.run([legacy, "--repo", str(fx.consumer), "config", "--inspect"],
                              cwd=fx.consumer, capture_output=True, text=True, timeout=180, check=False)
        self.assertNotEqual(proc.returncode, 0, "v0.14.x accepted a v0.15 bundle")

    # 9. One run of deps:prepare in a fixture with no package manifests: compiles and dispatches.
    def test_deps_prepare_helper_dispatches(self) -> None:
        fx = self.fixture()
        proc = run_effigy(["--repo", str(fx.consumer), "deps:prepare"], fx.consumer)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("unsupported ui setup target", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
