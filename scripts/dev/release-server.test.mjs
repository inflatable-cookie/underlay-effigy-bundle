import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { adapterKind, resolveStatic } from "./release-server.mjs";

function buildDir(files) {
  const root = mkdtempSync(join(tmpdir(), "release-build-"));
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), contents);
  }
  return root;
}

test("serves exact files, .html routes and directory indexes", () => {
  const root = buildDir({
    "200.html": "spa",
    "about.html": "about",
    "docs/index.html": "docs",
    "_app/immutable/app.js": "js",
  });
  assert.equal(resolveStatic(root, "/_app/immutable/app.js"), join(root, "_app/immutable/app.js"));
  assert.equal(resolveStatic(root, "/about"), join(root, "about.html"));
  assert.equal(resolveStatic(root, "/docs/"), join(root, "docs/index.html"));
  assert.equal(resolveStatic(root, "/about?x=1"), join(root, "about.html"));
});

test("unknown routes fall back to the SPA page", () => {
  const root = buildDir({ "index.html": "spa" });
  assert.equal(resolveStatic(root, "/admin/users/42"), join(root, "index.html"));
  assert.equal(resolveStatic(root, "/"), join(root, "index.html"));
});

test("the 200.html fallback wins over index.html", () => {
  const root = buildDir({ "200.html": "spa", "index.html": "home" });
  assert.equal(resolveStatic(root, "/missing"), join(root, "200.html"));
});

test("paths cannot escape the build directory", () => {
  const root = buildDir({ "index.html": "spa" });
  assert.equal(resolveStatic(root, "/%2e%2e/%2e%2e/etc/passwd"), join(root, "index.html"));
  assert.equal(resolveStatic(root, "/%E0%A4%A"), null);
});

test("no build output and no fallback serves nothing", () => {
  const root = buildDir({});
  assert.equal(resolveStatic(root, "/anything"), null);
});

test("adapter kind comes from svelte.config", () => {
  const node = buildDir({ "svelte.config.js": 'import adapter from "@sveltejs/adapter-node";' });
  const staticApp = buildDir({ "svelte.config.js": "import adapter from '@sveltejs/adapter-static';" });
  assert.equal(adapterKind(node), "node");
  assert.equal(adapterKind(staticApp), "static");
  assert.equal(adapterKind(buildDir({})), "static");
});
