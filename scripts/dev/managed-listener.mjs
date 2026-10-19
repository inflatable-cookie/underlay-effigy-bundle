// Shared glue for bundle-owned managed host listeners: Effigy's bind and
// report protocol, and the per-checkout public API config the front and admin
// apps compile in. Used by the Vite dev adapter and the release server.

import { spawnSync } from "node:child_process";
import { open, readFile, rename } from "node:fs/promises";
import { resolve } from "node:path";

export function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Effigy did not provide ${name}`);
  return value;
}

export function parseBind(raw) {
  const match = /^127\.0\.0\.1:(\d+)$/.exec(raw);
  if (!match) throw new Error(`managed listener requires an IPv4 loopback bind, got ${raw}`);
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid managed listener port in ${raw}`);
  }
  return { host: "127.0.0.1", port };
}

/** The managed listener's bind, report target and the profile's public URLs. */
export function managedContext() {
  const { host, port } = parseBind(required("EFFIGY_MANAGED_HOST_LISTENER_BIND"));
  const gatewayPort = Number(required("EFFIGY_PROFILE_GATEWAY_HTTPS_PORT"));
  if (!Number.isInteger(gatewayPort) || gatewayPort < 1 || gatewayPort > 65535) {
    throw new Error("EFFIGY_PROFILE_GATEWAY_HTTPS_PORT must be the gateway's actual HTTPS port");
  }
  const urls = {
    publicUrl: new URL(required("EFFIGY_PROFILE_PUBLIC_URL")),
    apiUrl: new URL(required("EFFIGY_MANAGED_HOST_API_PUBLIC_URL")),
    frontUrl: new URL(required("EFFIGY_PROFILE_FRONT_PUBLIC_URL")),
    adminUrl: new URL(required("EFFIGY_PROFILE_ADMIN_PUBLIC_URL")),
  };
  for (const url of Object.values(urls)) {
    if (!url.port && gatewayPort !== 443) url.port = String(gatewayPort);
    if (url.protocol !== "https:") throw new Error(`profile route must use HTTPS: ${url}`);
  }
  return {
    host,
    port,
    gatewayPort,
    reportPath: resolve(required("EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE")),
    generation: required("EFFIGY_MANAGED_HOST_LISTENER_GENERATION"),
    ...urls,
  };
}

/** Run the app's public config generator. Throws with its output on failure. */
export function generatePublicConfig(cwd) {
  const generator = process.env.EFFIGY_PROFILE_PUBLIC_CONFIG_GENERATOR || "scripts/generate-public-config.ts";
  const generatorPath = resolve(cwd, generator);
  if (generatorPath !== cwd && !generatorPath.startsWith(`${cwd}/`)) {
    throw new Error("the public API config generator must stay within the app checkout");
  }
  const generated = spawnSync("bun", [generatorPath], {
    cwd,
    env: process.env,
    encoding: "utf8",
    timeout: 120_000,
  });
  if (generated.error || generated.status !== 0) {
    const detail = (generated.stderr || generated.stdout || generated.error?.message || "").trim().split("\n").slice(-20).join("\n");
    throw new Error(`public API config generation failed (status ${generated.status ?? "spawn"})${detail ? `:\n${detail}` : ""}`);
  }
}

async function writeAtomically(path, contents) {
  const temporary = `${path}.${process.pid}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
}

/** Point the generated public config at this checkout's effective hostnames. */
export async function scopePublicConfig({ apiUrl, frontUrl, adminUrl }) {
  const publicConfigPath = resolve(
    process.env.EFFIGY_PROFILE_PUBLIC_CONFIG_FILE || "src/lib/config/public-api.generated.ts",
  );
  const existingConfig = await readFile(publicConfigPath, "utf8");
  const configMatch = existingConfig.match(/export const publicApiConfig = (\{[\s\S]*?\}) as const;/);
  if (!configMatch) throw new Error(`could not read existing public API config at ${publicConfigPath}`);
  const publicConfig = JSON.parse(configMatch[1]);
  if (typeof publicConfig.apiVersion !== "string") {
    throw new Error(`public API config has no apiVersion: ${publicConfigPath}`);
  }
  publicConfig.baseUrl = apiUrl.origin;
  publicConfig.frontUrl = frontUrl.origin;
  publicConfig.adminUrl = adminUrl.origin;
  await writeAtomically(
    publicConfigPath,
    `export const publicApiConfig = ${JSON.stringify(publicConfig, null, 2)} as const;\n`,
  );
}

/** Tell Effigy which socket this listener bound. */
export async function writeListenerReport({ reportPath, generation }, address) {
  await writeAtomically(
    reportPath,
    JSON.stringify({
      schema: "effigy.managed.host-listener-report.v1",
      generation,
      address: `${address.address}:${address.port}`,
    }),
  );
}

/** Resolve once SIGINT, SIGTERM or SIGHUP arrives. */
export function untilSignal() {
  return new Promise((resolveSignal) => {
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.once(signal, () => resolveSignal(signal));
  });
}
