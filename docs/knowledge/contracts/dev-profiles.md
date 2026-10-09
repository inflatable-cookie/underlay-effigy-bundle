# Development profiles and ownership

## Direction

The intended consumer development default is hybrid: isolated service
containers for Postgres, MinIO, Mailpit and DbGate, with Rust and Bun processes
on the host. `dev:container` retains the Linux whole-stack path. `dev:test`
provides a short-lived, worktree-isolated host and service environment without
automatically running full QA.

These are intended profiles, not a claim that the current bundle implements
them. Existing defaults remain container-based. New profile additions must be
opt-in and backward-compatible; switching a consumer's `dev` default requires
an explicit migration after qualification. Container-only use remains valid.

## Ownership

The bundle owns Rust and Vite adapters, service declarations, profile-specific
connection URLs, browser origins, HMR configuration and selector wiring.
Effigy owns language-agnostic execution, environment delivery, readiness and
gateway ownership primitives. Oxide separately owns Rust build and cache
management. The bundle must not introduce another supervisor, allocator or
cache manager to cover a missing Effigy primitive.

Host processes connect to services through reachable loopback endpoints.
Browser-facing HTTPS URLs are distinct from internal bind addresses. Qualified
profiles must prove SvelteKit origins and Vite HMR WebSocket connectivity
through the gateway. Host and Linux dependencies and build artifacts are not
interchangeable.

## Runtime identity and ports

An instance identity covers its checkout, runtime generation and profile.
Frontend, admin, API and additional Rust listeners have distinct owned
addresses. Prefer OS port zero with discovery of the actual listener where the
adapter supports it. Otherwise require exclusive allocation claims, strict
binding and bounded collision retry. A free-port probe is not a reservation.

Publish a route only after proving readiness of its owned listener. Keep the
actual address current across restart and reject foreign hostname takeover.
Cleanup affects only recorded instance resources. Neither age nor a missing
PID establishes that an allocation can be released; uncertain ownership must
remain explicit.

## Qualification boundary

Use private disposable consumer fixtures and isolated owned resources. Cover
two worktrees and a main-checkout identity starting simultaneously, occupied
ports, child restart, partial launch failure, interrupted cleanup and uncertain
ownership. Isolated teardown must preserve foreign processes and routes.
Assemble the branch from a private consumer and prove unchanged default inputs
and `sources.siblings = false`, following [release.md](release.md).

Existing live infrastructure is read-only. Profile qualification does not
authorize changes to Acow deployment, volumes, data or config; live gateway,
resolver or settings; the global executable; Queue/Nucleus scheduling; frozen
010; providers, workflows, releases or tags. Existing allocation-pruning and
consumer host-wiring findings remain separate evidence, not claimed repairs.

If supported interfaces cannot establish these properties, report the
smallest generic Effigy capability gap with an executable reproduction. A
blocked capability must not become an invented CLI or private protocol.

## Supported Effigy boundary and Reference execution — 2026-10-09

The final Effigy owner handover is source commit
`bd2dd667302250c7b8fed548c850567df2283038`. Qualification used its privately
built `effigy v0.14.1` binary (SHA-256
`ed44140738cc6e76e72ea9ee3ce23cad9aae243748d5833f3f8a15bba483aff2`).
The inspected source documents were `docs/knowledge/contracts/005-container-runtime-contract.md`
and `docs/guides/063-container-system-guide.md` in that exact Effigy checkout.

Effigy supports `containers.<name>.host_processes` declarations with
`listener.bind`, HTTP readiness, TLS route, and `depends_on`. An adapter
strictly binds `EFFIGY_MANAGED_HOST_LISTENER_BIND`, then writes
`effigy.managed.host-listener-report.v1` to
`EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE` and echoes
`EFFIGY_MANAGED_HOST_LISTENER_GENERATION`. Effigy verifies kernel socket
ownership and HTTP readiness before publication. Dependents receive current
`EFFIGY_MANAGED_HOST_<NAME>_INTERNAL_URL`, `_PUBLIC_URL`, `_STATE_FILE`,
and `_GENERATION` values and restart after a dependency endpoint or readiness
change. This supersedes the earlier qualification's missing-capability
description; do not infer that the Reference profile is ready.

Effigy private gateway mode is also supported. A caller-owned mode-0700 root
can be selected with `EFFIGY_GATEWAY_PRIVATE_STATE_ROOT` and
`--private-state-root`. Private TLS setup and startup report the fixture CA
without installing it or changing resolver, aliases, global gateway state, or
trust. A client must use the CA file and explicit name resolution/SNI. The
qualification used loopback-only listeners with the HTTPS port pinned to
`54321`; it did not use global TLS setup or the system trust store.

### Designated Reference receipts

The pilot source was a clean Underlay Reference checkout at
`16b35df4bebe920b14eca9d43abc626de44cb617`. It remained untouched. A private
main clone and two detached worktrees retained `sources.siblings = false`,
the `workspace-rust-bun` catalog, the default Reference project name, and
container ports 41001/41002/41003. Effigy reported three distinct checkout
scopes, HTTPS host maps and container service port sets. The three isolated
Colima stacks used separate project names and loopback-published Postgres,
Mailpit, DbGate and workspace ports.

The bundle adds opt-in Rust and Vite adapter programs at
`scripts/dev/managed-rust-listener.py` and
`scripts/dev/managed-vite-listener.mjs`. The Rust adapter starts the actual
Reference `acme-api/api` task with Effigy's loopback bind preference, discovers
its listener within that task's process tree, and writes the versioned report.
The Vite adapter loads the consumer's installed Vite/SvelteKit configuration,
uses Effigy's managed API public URL, writes the generated client URL module,
sets SvelteKit `ORIGIN`, and configures HMR for the gateway's actual HTTPS
port. Fixture-only configuration requested port zero and distinct pilot
domains; no consumer default or source checkout was changed.

The Reference API compiled and reached Postgres over its host loopback URL;
migration notices were recorded. It bound a real listener at
`127.0.0.1:52177`, and an explicit Host-header GET to
`http://127.0.0.1:52177/v1/health` returned `200`. The adapter wrote the
generation-bound listener report. However, the exact-source Effigy supervisor
left its state at `starting`, did not publish the API route, then terminated
the child and recorded `failed` after 240 seconds with
`timed out after 240s waiting for an owned ready managed host listener`.
The report and direct HTTP success did not satisfy Effigy's owned-listener
verification on this macOS run. The result does not establish why verification
timed out; route publication remains fail-closed.

The two surviving worktree service stacks accepted SMTP EHLO at
`127.0.0.1:8526` and `127.0.0.1:8426`. The main stack had already rolled back
after the managed API listener failure, so its SMTP service was absent. This
does not qualify MinIO: the disposable catalog used a stub after the pinned
image was denied by both registries.

The API was the dependency for both Vite/SvelteKit listeners, so those
processes did not start. The private gateway setup stayed scoped to its
fixture CA; the earlier global `mkcert -install` denial is superseded. A
verified client handshake to the registered `acme.test` route received
`TLSV1_ALERT_ACCESS_DENIED`, so private HTTPS/browser connectivity is still
blocked. SvelteKit request origins, HMR WebSocket, listener restart/route
replacement, partial failure recovery, uncertain-owner handling, and isolated
teardown were not proven.

The pinned MinIO image could not be pulled from either configured public
registry (Docker Hub denied the image scope; Quay returned 401). To continue
the unaffected Reference build/configuration and API/Postgres attempt, only
the private disposable consumer catalog used a BusyBox stub on the MinIO
service ports. This is not MinIO connectivity evidence and does not qualify
the exact default container startup. The standard Reference default ports,
image declarations and bundle selectors were not changed.

### Current assurance

The bundle's default container profile and fixed ports remain unchanged.
Container-only plans, private assembly with `sources.siblings = false`, and
generic synthetic Rust/Bun collision checks are evidence for those specific
cases only. The Reference hybrid and `dev:test` profiles are unavailable:
Effigy's supported contract exists, but owned API route publication did not
complete in the designated macOS pilot. MinIO, gateway app connectivity,
SvelteKit origins/HMR, restart propagation, interrupted cleanup, and
three-instance managed application concurrency remain unqualified. Do not
switch a consumer's default or claim either profile ready from these receipts.

The private Reference selector accepts
`UNDERLAY_PROFILE_REFERENCE_FIXTURE_ROOT` to inspect an already prepared
three-instance pilot without writing to it or starting/stopping resources.
The qualification scripts require both
`UNDERLAY_PROFILE_EFFIGY_SOURCE` and
`UNDERLAY_PROFILE_EFFIGY_BIN`, pinned to the exact handover source and
binary hash above. They do not select a global binary implicitly.
