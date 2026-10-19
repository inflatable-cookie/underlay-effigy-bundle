#!/usr/bin/env node

import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  generatePublicConfig,
  managedContext,
  scopePublicConfig,
  writeListenerReport,
} from "./managed-listener.mjs";

async function main() {
  const context = managedContext();
  const { host, port, gatewayPort, publicUrl } = context;
  const cwd = process.cwd();
  generatePublicConfig(cwd);
  await scopePublicConfig(context);

  const requireFromConsumer = createRequire(pathToFileURL(join(cwd, "package.json")));
  const viteEntry = requireFromConsumer.resolve("vite");
  const { createServer } = await import(pathToFileURL(viteEntry).href);
  const configFile = resolve(process.env.EFFIGY_PROFILE_VITE_CONFIG || "vite.config.ts");

  process.env.ORIGIN = publicUrl.origin;
  process.env.EFFIGY_PROFILE_PUBLIC_URL = publicUrl.origin;
  process.env.EFFIGY_PROFILE_PUBLIC_ORIGIN = "true";
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
        clientPort: gatewayPort,
      },
    },
  });

  await server.listen();
  const address = server.httpServer?.address();
  if (!address || typeof address === "string" || address.address !== host) {
    await server.close();
    throw new Error("Vite did not bind the requested IPv4 loopback socket");
  }
  await writeListenerReport(context, address);

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
