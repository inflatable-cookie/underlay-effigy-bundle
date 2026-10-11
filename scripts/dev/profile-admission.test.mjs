import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./profile_admission_test.py", import.meta.url));

test("opt-in profile admission and cleanup contracts", () => {
  const result = spawnSync("python3", ["-u", script], {
    encoding: "utf8",
    timeout: 25_000,
    maxBuffer: 2_000_000,
  });
  if (result.error) {
    assert.fail(`${result.error}\n${result.stdout || ""}\n${result.stderr || ""}`);
  }
  assert.equal(result.status, 0, `${result.stdout || ""}\n${result.stderr || ""}`);
});

import { decodeContext } from "./context-diagnostic.mjs";

test("context errors retain approved phase and discard seeded payloads", () => {
  const record = { schema: "underlay.profile-context-error.v1", phase: "service-port",
    operation: "postgres", error_class: "ProfileError", message: "binding_conflict",
    password: "SEEDED_PASSWORD", body: "SEEDED_BODY" };
  assert.throws(() => decodeContext({ status: 1, stdout: "SEEDED_STDOUT",
    stderr: `SEEDED_TOKEN\nUNDERLAY_CONTEXT_ERROR ${JSON.stringify(record)}\n` }), error => {
    assert.match(error.message, /service-port/);
    assert.match(error.message, /binding_conflict/);
    assert.doesNotMatch(error.message, /SEEDED/);
    return true;
  });
  for (const result of [
    { status: 1, stderr: "SEEDED_TOKEN", stdout: "SEEDED_STDOUT" },
    { error: { code: "ETIMEDOUT", message: "SEEDED_SECRET_PATH" }, status: null },
    { status: 0, stdout: "SEEDED_INVALID_BODY" },
    { status: 1, stderr: `UNDERLAY_CONTEXT_ERROR ${JSON.stringify({ ...record, phase: "SEEDED_PHASE" })}` },
  ]) {
    assert.throws(() => decodeContext(result), error => {
      assert.match(error.message, /UNDERLAY_CONTEXT_ERROR/);
      assert.doesNotMatch(error.message, /SEEDED/);
      return true;
    });
  }
  assert.deepEqual(decodeContext({ status: 0, stdout: '{"https_port":8443}' }), { https_port: 8443 });
});
