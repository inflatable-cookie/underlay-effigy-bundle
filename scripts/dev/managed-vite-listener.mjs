#!/usr/bin/env node

import { createRequire } from "node:module";
import { open, readFile, rename } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Effigy did not provide ${name}`);
  return value;
}

function parseBind(raw) {
  const match = /^127\.0\.0\.1:(\d+)$/.exec(raw);
  if (!match) throw new Error(`managed Vite listener requires an IPv4 loopback bind, got ${raw}`);
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid managed listener port in ${raw}`);
  }
  return { host: "127.0.0.1", port };
}

async function main() {
  const { host, port } = parseBind(required("EFFIGY_MANAGED_HOST_LISTENER_BIND"));
  const reportPath = resolve(required("EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE"));
  const generation = required("EFFIGY_MANAGED_HOST_LISTENER_GENERATION");
  const publicUrl = new URL(required("EFFIGY_PROFILE_PUBLIC_URL"));
  const apiUrl = new URL(required("EFFIGY_MANAGED_HOST_API_PUBLIC_URL"));
  const frontUrl = new URL(required("EFFIGY_PROFILE_FRONT_PUBLIC_URL"));
  const adminUrl = new URL(required("EFFIGY_PROFILE_ADMIN_PUBLIC_URL"));
  const hmrPort = Number(required("EFFIGY_PROFILE_GATEWAY_HTTPS_PORT"));
  if (!Number.isInteger(hmrPort) || hmrPort < 1 || hmrPort > 65535) {
    throw new Error("EFFIGY_PROFILE_GATEWAY_HTTPS_PORT must be the gateway's actual HTTPS port");
  }
  for (const url of [publicUrl, apiUrl, frontUrl, adminUrl]) {
    if (!url.port && hmrPort !== 443) url.port = String(hmrPort);
    if (url.protocol !== "https:") throw new Error(`profile route must use HTTPS: ${url}`);
  }
  const cwd = process.cwd();
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
  const configTemporary = `${publicConfigPath}.${process.pid}.tmp`;
  const configHandle = await open(configTemporary, "wx", 0o600);
  try {
    await configHandle.writeFile(
      `export const publicApiConfig = ${JSON.stringify(publicConfig, null, 2)} as const;\n`,
    );
    await configHandle.sync();
  } finally {
    await configHandle.close();
  }
  await rename(configTemporary, publicConfigPath);

  const requireFromConsumer = createRequire(pathToFileURL(join(cwd, "package.json")));
  const viteEntry = requireFromConsumer.resolve("vite");
  const { createServer } = await import(pathToFileURL(viteEntry).href);
  const configFile = resolve(process.env.EFFIGY_PROFILE_VITE_CONFIG || "vite.config.ts");

  process.env.ORIGIN = publicUrl.origin;
  const server = await createServer({
    configFile,
    server: {
      host,
      port,
      strictPort: true,
      origin: publicUrl.origin,
      allowedHosts: [publicUrl.hostname],
      hmr: {
        protocol: publicUrl.protocol === "https:" ? "wss" : "ws",
        host: publicUrl.hostname,
        clientPort: hmrPort,
      },
    },
  });

  await server.listen();
  const address = server.httpServer?.address();
  if (!address || typeof address === "string" || address.address !== host) {
    await server.close();
    throw new Error("Vite did not bind the requested IPv4 loopback socket");
  }

  const report = {
    schema: "effigy.managed.host-listener-report.v1",
    generation,
    address: `${address.address}:${address.port}`,
  };
  const temporary = `${reportPath}.${process.pid}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(JSON.stringify(report));
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, reportPath);

  server.printUrls();
  await new Promise((resolveClose) => {
    let closing = false;
    const close = async () => {
      if (closing) return;
      closing = true;
      await server.close();
      resolveClose();
    };
    process.once("SIGINT", close);
    process.once("SIGTERM", close);
    process.once("SIGHUP", close);
    server.httpServer?.once("close", () => resolveClose());
  });
}

main().catch((error) => {
  console.error(`managed Vite listener adapter failed: ${error?.stack || error}`);
  process.exitCode = 1;
});
