/**
 * Opt-in SvelteKit development hook for applications served behind Effigy's
 * HTTPS gateway. The gateway terminates TLS, so SvelteKit's Vite middleware
 * sees an HTTP request even though the browser connected with HTTPS.
 *
 * The configured public origin is the only authority accepted here. Incoming
 * Host and forwarded headers can confirm that authority, but cannot choose it.
 */

function fail(message) {
  throw new Error(`invalid public-origin request: ${message}`);
}

function configuredOrigin(raw) {
  if (typeof raw !== "string" || raw.length === 0) {
    fail("a configured HTTPS public origin is required when enabled");
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    fail("configured origin is not a URL");
  }

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    raw !== url.origin
  ) {
    fail("configured origin must be a canonical HTTPS origin without a path");
  }

  return url.origin;
}

function parseAuthority(value, headerName) {
  if (!value || value.includes(",") || /[\s/@?#]/.test(value)) {
    fail(`${headerName} is missing or malformed`);
  }

  let url;
  try {
    url = new URL(`https://${value}/`);
  } catch {
    fail(`${headerName} is malformed`);
  }

  if (
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    fail(`${headerName} is malformed`);
  }

  let explicitPort = "";
  if (value.startsWith("[")) {
    const closing = value.indexOf("]");
    if (closing < 0) fail(`${headerName} is malformed`);
    const suffix = value.slice(closing + 1);
    if (suffix !== "") {
      if (!/^:\d+$/.test(suffix)) fail(`${headerName} is malformed`);
      explicitPort = suffix.slice(1);
    }
  } else {
    const colon = value.lastIndexOf(":");
    if (colon >= 0) {
      explicitPort = value.slice(colon + 1);
      if (!/^\d+$/.test(explicitPort)) fail(`${headerName} is malformed`);
    }
  }

  return { origin: url.origin, hostname: url.hostname.toLowerCase(), explicitPort };
}

function authorityOrigin(value, headerName) {
  return parseAuthority(value, headerName).origin;
}

function matchesConfiguredHost(authority, expected, allowMissingPort) {
  return (
    authority.hostname === expected.hostname.toLowerCase() &&
    (authority.explicitPort === expected.port ||
      (allowMissingPort && authority.explicitPort === ""))
  );
}

function verifyOriginHeader(value, expectedOrigin, method) {
  if (value === null) return;
  if (!value || value === "null") fail("Origin is empty or opaque");

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("Origin is malformed");
  }

  if (
    parsed.origin !== value ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    ((method !== "GET" && method !== "HEAD" && method !== "OPTIONS") &&
      parsed.origin !== expectedOrigin)
  ) {
    fail("unsafe request Origin does not match the configured public origin");
  }
}

function requestAtPublicOrigin(request, eventUrl, expectedOrigin, readinessPath) {
  const headers = request.headers;
  if (!headers || typeof headers.get !== "function") {
    fail("Request headers are unavailable");
  }

  const expected = new URL(expectedOrigin);
  const incomingUrl = new URL(request.url);
  const svelteUrl = new URL(eventUrl);
  const host = headers.get("host");
  const originHeader = headers.get("origin");
  let hostMatchesPublicOrigin = false;
  let readinessAuthority;
  try {
    readinessAuthority = parseAuthority(host, "Host");
  } catch {
    readinessAuthority = null;
  }
  const localReadinessProbe =
    (request.method === "GET" || request.method === "HEAD") &&
    svelteUrl.pathname === readinessPath &&
    svelteUrl.search === "" &&
    incomingUrl.protocol === "http:" &&
    incomingUrl.pathname === readinessPath &&
    incomingUrl.search === "" &&
    originHeader === null &&
    readinessAuthority !== null &&
    matchesConfiguredHost(readinessAuthority, expected, true);
  if (!localReadinessProbe && authorityOrigin(host, "Host") !== expected.origin) {
    fail("Host does not match the configured public origin");
  }
  hostMatchesPublicOrigin = !localReadinessProbe;

  const forwardedHost = headers.get("x-forwarded-host");
  const forwardedProto = headers.get("x-forwarded-proto");
  if (forwardedProto !== null && forwardedProto !== "https") {
    fail("X-Forwarded-Proto must be exactly https when supplied");
  }

  if (forwardedHost !== null) {
    const parsedForwardedHost = parseAuthority(forwardedHost, "X-Forwarded-Host");
    const exactPublicAuthority = parsedForwardedHost.origin === expected.origin;
    // Effigy's gateway currently strips the request port when it constructs
    // X-Forwarded-Host. Permit that hostname-only value only after the actual
    // Host header has independently matched the configured full authority
    // and the gateway has marked the request as HTTPS. The forwarded value
    // still cannot select or widen the public origin.
    const gatewayHostnameOnly =
      parsedForwardedHost.explicitPort === "" &&
      parsedForwardedHost.hostname === expected.hostname.toLowerCase() &&
      hostMatchesPublicOrigin &&
      forwardedProto === "https";
    if (!exactPublicAuthority && !gatewayHostnameOnly) {
      fail("X-Forwarded-Host does not match the configured public origin");
    }
  }

  verifyOriginHeader(originHeader, expected.origin, request.method);

  if (
    incomingUrl.pathname !== svelteUrl.pathname ||
    incomingUrl.search !== svelteUrl.search
  ) {
    fail("SvelteKit and Request paths do not agree");
  }

  return new URL(`${svelteUrl.pathname}${svelteUrl.search}`, expected.origin);
}

function requestWithUrl(request, url) {
  const method = request.method;
  const init = {
    method,
    headers: request.headers,
    signal: request.signal,
    credentials: request.credentials,
    mode: request.mode,
    cache: request.cache,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    integrity: request.integrity,
    keepalive: request.keepalive,
  };

  if (request.body !== null) {
    if (method === "GET" || method === "HEAD") {
      fail(`${method} request unexpectedly has a body`);
    }
    init.body = request.body;
    // Node's Fetch implementation requires this for a forwarded stream.
    init.duplex = "half";
  }

  // Pass the original body stream through. This does not read, clone, or
  // reconstruct the payload; the request consumer remains the sole reader.
  return new Request(url, init);
}

export function normalizeSvelteKitEvent(event, publicOrigin, readinessPath = "/__effigy/ready") {
  const expectedOrigin = configuredOrigin(publicOrigin);
  const requestUrl = requestAtPublicOrigin(
    event.request,
    event.url,
    expectedOrigin,
    readinessPath,
  );
  const request = requestWithUrl(event.request, requestUrl);

  return new Proxy(event, {
    get(target, property, receiver) {
      if (property === "url") return requestUrl;
      if (property === "request") return request;
      return Reflect.get(target, property, target);
    },
  });
}

/** Wrap an existing SvelteKit handle without changing default/non-dev paths. */
export function withSvelteKitPublicOrigin(handle, options = {}) {
  return async function publicOriginHandle(input) {
    if (!options.enabled) {
      return handle ? handle(input) : input.resolve(input.event);
    }

    const event = normalizeSvelteKitEvent(
      input.event,
      options.publicOrigin,
      options.readinessPath || "/__effigy/ready",
    );
    const wrapped = { ...input, event };
    return handle ? handle(wrapped) : input.resolve(event);
  };
}
