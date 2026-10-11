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
