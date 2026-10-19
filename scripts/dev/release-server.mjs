#!/usr/bin/env node
// Serve a SvelteKit app's production build with no Vite dev server in the
// request path. Vite only builds: `vite build` in watch mode rebuilds the
// production output on save, and this process serves whatever the adapter
// last wrote. No HMR; refresh the browser after a rebuild.
//
//   adapter-static  build/ is served directly with the SPA fallback page.
//   adapter-node    build/index.js runs as a child on a private port behind
//                   this server and restarts after each rebuild.
//
// Run as an Effigy managed host listener (hybrid release), or with
// `--host H --port N` on a fixed port (container release).

import { spawn } from "node:child_process";
import { createReadStream, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createServer, request } from "node:http";
import { createRequire } from "node:module";
import { connect, createServer as createNetServer } from "node:net";
import { extname, join, normalize, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import {
  generatePublicConfig,
  managedContext,
  scopePublicConfig,
  untilSignal,
  writeListenerReport,
} from "./managed-listener.mjs";

const BUILD_DIR = resolve(process.env.EFFIGY_RELEASE_BUILD_DIR || "build");
const FALLBACKS = ["200.html", "index.html", "404.html"];
const WATCH_IGNORED = ["**/.svelte-kit/**", "**/build/**", "**/node_modules/**", "**/.effigy/**", "**/*.generated.ts"];
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml",
  ".webmanifest": "application/manifest+json",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".map": "application/json",
};

const log = (message) => console.log(`[release] ${message}`);

function args(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const [key, value] = [argv[index], argv[index + 1]];
    if (key === "--host" || key === "--port") {
      options[key.slice(2)] = value;
      index += 1;
    } else throw new Error(`unknown argument ${key}`);
  }
  return options;
}

/** A path under BUILD_DIR to serve for this URL path, or null. */
export function resolveStatic(buildDir, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.split("?")[0]);
  } catch {
    return null;
  }
  const relative = normalize(decoded).replace(/^([/\\])+/, "");
  const base = resolve(buildDir);
  for (const candidate of [relative, `${relative}.html`, join(relative, "index.html")]) {
    const full = resolve(base, candidate);
    if (full !== base && !full.startsWith(base + sep)) return null;
    if (existsSync(full) && statSync(full).isFile()) return full;
  }
  const fallback = FALLBACKS.map((name) => join(base, name)).find((path) => existsSync(path));
  return fallback || null;
}

function serveStatic(req, res) {
  const file = resolveStatic(BUILD_DIR, req.url || "/");
  if (!file) {
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    return;
  }
  const immutable = (req.url || "").startsWith("/_app/immutable/");
  res.writeHead(200, {
    "content-type": TYPES[extname(file)] || "application/octet-stream",
    "cache-control": immutable ? "public, max-age=31536000, immutable" : "no-cache",
  });
  if (req.method === "HEAD") res.end();
  else createReadStream(file).pipe(res);
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const probe = createNetServer().once("error", reject).listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolvePort(port));
    });
  });
}

async function waitForPort(port, child, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`node server exited with ${child.exitCode}`);
    const open = await new Promise((done) => {
      const socket = connect(port, "127.0.0.1", () => socket.end(() => done(true))).once("error", () => done(false));
    });
    if (open) return;
    await new Promise((wait) => setTimeout(wait, 150));
  }
  throw new Error("node server did not start listening");
}

/** adapter-node output behind this server, restarted after each rebuild. */
class NodeApp {
  constructor(env) {
    this.env = env;
    this.child = null;
    this.port = null;
  }

  async restart() {
    await this.stop();
    const port = await freePort();
    const runtime = process.env.EFFIGY_RELEASE_NODE_RUNTIME || "node";
    const child = spawn(runtime, [join(BUILD_DIR, "index.js")], {
      env: { ...process.env, ...this.env, HOST: "127.0.0.1", PORT: String(port) },
      stdio: "inherit",
    });
    this.child = child;
    await waitForPort(port, child);
    this.port = port;
  }

  async stop() {
    const child = this.child;
    this.child = null;
    this.port = null;
    if (!child || child.exitCode !== null) return;
    await new Promise((done) => {
      const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
      child.once("exit", () => {
        clearTimeout(timer);
        done();
      });
      child.kill("SIGTERM");
    });
  }

  proxy(req, res) {
    if (!this.port) {
      res.writeHead(503, { "content-type": "text/plain", "retry-after": "1" }).end("restarting after rebuild");
      return;
    }
    const upstream = request(
      { host: "127.0.0.1", port: this.port, method: req.method, path: req.url, headers: req.headers },
      (reply) => {
        res.writeHead(reply.statusCode || 502, reply.rawHeaders);
        reply.pipe(res);
      },
    );
    upstream.once("error", () => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end("node server unavailable");
    });
    req.pipe(upstream);
  }

  upgrade(req, socket, head) {
    if (!this.port) return socket.destroy();
    const upstream = connect(this.port, "127.0.0.1", () => {
      const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
      for (let index = 0; index < req.rawHeaders.length; index += 2) {
        lines.push(`${req.rawHeaders[index]}: ${req.rawHeaders[index + 1]}`);
      }
      upstream.write(`${lines.join("\r\n")}\r\n\r\n`);
      if (head?.length) upstream.write(head);
      upstream.pipe(socket).pipe(upstream);
    });
    upstream.once("error", () => socket.destroy());
    socket.once("error", () => upstream.destroy());
  }
}

/** "node" for adapter-node apps, otherwise "static". */
export function adapterKind(cwd) {
  for (const name of ["svelte.config.js", "svelte.config.mjs", "svelte.config.ts"]) {
    const path = join(cwd, name);
    if (existsSync(path)) return /@sveltejs\/adapter-node/.test(readFileSync(path, "utf8")) ? "node" : "static";
  }
  return "static";
}

function newestMtime(dir) {
  let newest = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    newest = Math.max(newest, entry.isDirectory() ? newestMtime(path) : statSync(path).mtimeMs);
  }
  return newest;
}

/** The adapter writes after Vite reports the bundle done; wait for it to finish. */
async function adapterOutput(kind, since, timeoutMs = 180_000) {
  const marker = kind === "node" ? join(BUILD_DIR, "handler.js") : null;
  const deadline = Date.now() + timeoutMs;
  let previous = -1;
  while (Date.now() < deadline) {
    await new Promise((wait) => setTimeout(wait, 750));
    if (!existsSync(BUILD_DIR) || (marker && !existsSync(marker))) continue;
    const newest = newestMtime(BUILD_DIR);
    if (newest >= since && newest === previous) return;
    previous = newest;
  }
  throw new Error(`adapter output did not settle in ${BUILD_DIR}`);
}

/** Start `vite build` in watch mode; call onBuilt after every successful build. */
async function watchBuild(cwd, onBuilt) {
  const requireFromConsumer = createRequire(pathToFileURL(join(cwd, "package.json")));
  const { build } = await import(pathToFileURL(requireFromConsumer.resolve("vite")).href);
  const watcher = await build({
    configFile: resolve(process.env.EFFIGY_PROFILE_VITE_CONFIG || "vite.config.ts"),
    mode: "production",
    build: { watch: { exclude: WATCH_IGNORED, chokidar: { ignored: WATCH_IGNORED } } },
  });
  let started = Date.now();
  let failed = false;
  watcher.on("event", (event) => {
    if (event.code === "START") {
      started = Date.now();
      failed = false;
      log("building...");
    } else if (event.code === "BUNDLE_END") {
      event.result?.close?.();
    } else if (event.code === "ERROR") {
      failed = true;
      event.result?.close?.();
      log(`build failed; still serving the previous build:\n${event.error?.message || event.error}`);
    } else if (event.code === "END" && !failed) {
      onBuilt(started);
    }
  });
  return watcher;
}

async function main() {
  const options = args(process.argv.slice(2));
  const managed = !options.port;
  const cwd = process.cwd();
  const context = managed ? managedContext() : null;

  // Release builds, but with this profile's hostnames and dev config.
  process.env.NODE_ENV = "production";
  generatePublicConfig(cwd);
  if (managed) {
    await scopePublicConfig(context);
    process.env.EFFIGY_PROFILE_PUBLIC_URL = context.publicUrl.origin;
    process.env.EFFIGY_PROFILE_PUBLIC_ORIGIN = "true";
  }

  // adapter-node trusts the gateway's forwarding headers for its origin, so
  // scoped worktree hostnames work without knowing them here.
  const nodeEnv = managed
    ? { ORIGIN: context.publicUrl.origin }
    : { PROTOCOL_HEADER: "x-forwarded-proto", HOST_HEADER: "x-forwarded-host" };
  const nodeApp = new NodeApp(nodeEnv);
  const builtKind = adapterKind(cwd);
  let kind = null;
  let restarting = Promise.resolve();

  const server = createServer((req, res) => {
    if (!kind) {
      res.writeHead(503, { "content-type": "text/plain", "retry-after": "2" }).end("first release build in progress");
    } else if (kind === "node") {
      nodeApp.proxy(req, res);
    } else {
      serveStatic(req, res);
    }
  });
  server.on("upgrade", (req, socket, head) => (kind === "node" ? nodeApp.upgrade(req, socket, head) : socket.destroy()));

  const host = managed ? context.host : options.host || "0.0.0.0";
  const port = managed ? context.port : Number(options.port);
  await new Promise((listening, reject) => server.once("error", reject).listen(port, host, listening));
  const address = server.address();
  if (managed) {
    if (!address || typeof address === "string" || address.address !== host) {
      throw new Error("release server did not bind the requested IPv4 loopback socket");
    }
    await writeListenerReport(context, address);
  }
  log(`listening on ${address.address}:${address.port}; building ${cwd}`);

  const watcher = await watchBuild(cwd, (started) => {
    restarting = restarting.then(async () => {
      try {
        await adapterOutput(builtKind, started);
        if (builtKind === "node") await nodeApp.restart();
        kind = builtKind;
        log(`serving ${builtKind} build (${Date.now() - started}ms)`);
      } catch (error) {
        log(`could not start the build: ${error?.message || error}`);
      }
    });
  });

  await untilSignal();
  // Shutdown must settle quickly: the app first, then the socket, and the
  // watcher only within a deadline (closing it mid-build can stall).
  setTimeout(() => process.exit(0), 8_000).unref();
  await nodeApp.stop();
  server.closeAllConnections?.();
  await new Promise((closed) => server.close(closed));
  await Promise.race([watcher.close(), new Promise((wait) => setTimeout(wait, 3_000))]);
  process.exit(0);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`release server failed: ${error?.stack || error}`);
    process.exit(1);
  });
}
