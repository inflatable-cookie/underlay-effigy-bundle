import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeSvelteKitEvent,
  withSvelteKitPublicOrigin,
} from "./sveltekit-public-origin.mjs";

const publicOrigin = "https://front.acme.test:5443";

function eventFor({
  method = "GET",
  body,
  host = "front.acme.test:5443",
  forwardedHost = "front.acme.test:5443",
  forwardedProto = "https",
  origin = null,
  path = "/browse/item?tab=files",
  requestAddress = "http://127.0.0.1:41003",
} = {}) {
  const headers = new Headers({ host });
  if (forwardedHost !== null) headers.set("x-forwarded-host", forwardedHost);
  if (forwardedProto !== null) headers.set("x-forwarded-proto", forwardedProto);
  if (origin !== null) headers.set("origin", origin);
  headers.set("cookie", "session=fixture");
  const request = new Request(`${requestAddress}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body, duplex: "half" }),
  });
  return { url: new URL(request.url), request, locals: { preserved: true } };
}

test("opt-in event gets the configured HTTPS origin and retains path/query", () => {
  const event = normalizeSvelteKitEvent(eventFor(), publicOrigin);
  assert.equal(event.url.href, `${publicOrigin}/browse/item?tab=files`);
  assert.equal(event.request.url, `${publicOrigin}/browse/item?tab=files`);
});

test("disabled wrapper keeps the original event and request unchanged", async () => {
  const event = eventFor();
  let received;
  const wrapped = withSvelteKitPublicOrigin(
    async ({ event: actual }) => {
      received = actual;
      return "handled";
    },
    { enabled: false },
  );
  assert.equal(await wrapped({ event, resolve: () => "resolved" }), "handled");
  assert.equal(received, event);
  assert.equal(received.request.url, "http://127.0.0.1:41003/browse/item?tab=files");
});

test("enabled wrapper preserves the existing hook and resolve chain", async () => {
  const event = eventFor();
  const calls = [];
  const wrapped = withSvelteKitPublicOrigin(
    async ({ event: normalized, resolve }) => {
      calls.push("existing-handle");
      normalized.locals.chained = true;
      return resolve(normalized);
    },
    { enabled: true, publicOrigin },
  );
  const result = await wrapped({
    event,
    resolve: async (normalized) => {
      calls.push("resolve");
      assert.equal(normalized.url.origin, publicOrigin);
      assert.equal(normalized.request.url, `${publicOrigin}/browse/item?tab=files`);
      return "response";
    },
  });
  assert.equal(result, "response");
  assert.deepEqual(calls, ["existing-handle", "resolve"]);
  assert.equal(event.locals.chained, true);
});

test("unsafe method, body stream, and request headers pass through", async () => {
  const original = eventFor({
    method: "POST",
    body: JSON.stringify({ value: "preserve me" }),
    origin: publicOrigin,
  });
  const normalized = normalizeSvelteKitEvent(original, publicOrigin);
  assert.equal(normalized.request.method, "POST");
  assert.equal(normalized.request.headers.get("cookie"), "session=fixture");
  assert.equal(normalized.request.headers.get("origin"), publicOrigin);
  assert.equal(await normalized.request.text(), JSON.stringify({ value: "preserve me" }));
});

test("missing or malformed host authority is rejected", () => {
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ host: "" }), publicOrigin),
    /Host is missing or malformed/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ host: "foreign.test:5443" }), publicOrigin),
    /Host does not match/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ host: "front.acme.test:5443,foreign.test" }), publicOrigin),
    /Host is missing or malformed/,
  );
});

test("only the exact safe readiness request may omit the gateway port", () => {
  const localReady = normalizeSvelteKitEvent(
    eventFor({
      host: "front.acme.test",
      forwardedHost: null,
      forwardedProto: null,
      path: "/__effigy/ready",
      requestAddress: "http://127.0.0.1:62904",
    }),
    publicOrigin,
  );
  assert.equal(localReady.url.origin, publicOrigin);
  assert.equal(localReady.request.url, `${publicOrigin}/__effigy/ready`);

  for (const options of [
    { path: "/", requestAddress: "http://127.0.0.1:62904" },
    { method: "POST", path: "/__effigy/ready", requestAddress: "http://127.0.0.1:62904" },
    {
      path: "/__effigy/ready",
      requestAddress: "http://127.0.0.1:62904",
      origin: publicOrigin,
    },
  ]) {
    assert.throws(
      () => normalizeSvelteKitEvent(
        eventFor({
          host: "front.acme.test",
          forwardedHost: null,
          forwardedProto: null,
          ...options,
        }),
        publicOrigin,
      ),
      /Host does not match/,
    );
  }

  for (const host of ["foreign.test", "front.acme.test:5444"]) {
    assert.throws(
      () => normalizeSvelteKitEvent(
        eventFor({
          host,
          forwardedHost: null,
          forwardedProto: null,
          path: "/__effigy/ready",
          requestAddress: "http://127.0.0.1:62904",
        }),
        publicOrigin,
      ),
      /Host does not match/,
    );
  }
});

test("forwarded host and scheme are validated when supplied", () => {
  const gatewayPortStripped = normalizeSvelteKitEvent(
    eventFor({ forwardedHost: "front.acme.test" }),
    publicOrigin,
  );
  assert.equal(gatewayPortStripped.url.origin, publicOrigin);
  assert.equal(gatewayPortStripped.request.url, `${publicOrigin}/browse/item?tab=files`);

  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ forwardedHost: "foreign.test:5443" }), publicOrigin),
    /X-Forwarded-Host does not match/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ forwardedHost: "front.acme.test:5444" }), publicOrigin),
    /X-Forwarded-Host does not match/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(
      eventFor({ forwardedHost: "front.acme.test", forwardedProto: null }),
      publicOrigin,
    ),
    /X-Forwarded-Host does not match/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ forwardedHost: "foreign.test:5443,front.acme.test:5443" }), publicOrigin),
    /X-Forwarded-Host is missing or malformed/,
  );
  assert.throws(
    () => normalizeSvelteKitEvent(eventFor({ forwardedProto: "http" }), publicOrigin),
    /X-Forwarded-Proto must be exactly https/,
  );
});

test("foreign, malformed, and opaque browser origins are rejected", () => {
  for (const origin of ["https://foreign.test:5443", "not a URL", "null"]) {
    assert.throws(
      () => normalizeSvelteKitEvent(eventFor({ method: "POST", origin }), publicOrigin),
      /Origin/,
    );
  }
});

test("foreign Origin on a safe GET does not select or change the public authority", () => {
  const normalized = normalizeSvelteKitEvent(
    eventFor({ origin: "https://foreign.test:5443" }),
    publicOrigin,
  );
  assert.equal(normalized.url.origin, publicOrigin);
  assert.equal(normalized.request.url, `${publicOrigin}/browse/item?tab=files`);
});

test("configured public origin must be canonical HTTPS origin", () => {
  for (const invalid of [
    "http://front.acme.test:5443",
    "https://front.acme.test:5443/path",
    "https://user@front.acme.test:5443",
  ]) {
    assert.throws(
      () => normalizeSvelteKitEvent(eventFor(), invalid),
      /configured origin/,
    );
  }
});
