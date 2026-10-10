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

## Supported mechanism

Qualification uses Effigy source
`2f7b1819fd0e72afff18a6053be424719ecf71fc` and its private `effigy v0.14.1`
binary, SHA-256
`2f4f888c76f424d41cc981881bc544a14fb82f024c0c50a2e3b5022bd4fb16fc`.
The scripts require explicit source and binary paths and verify both identities.
The owning interfaces are Effigy's contract 005 managed host listener routes
and guide 063 managed host listeners/private gateway at that source.

Effigy supports `containers.<name>.host_processes` with `listener.bind`, HTTP
readiness, a TLS route, and `depends_on`. An adapter strictly binds
`EFFIGY_MANAGED_HOST_LISTENER_BIND`, then writes
`effigy.managed.host-listener-report.v1` to
`EFFIGY_MANAGED_HOST_LISTENER_REPORT_FILE`, echoing
`EFFIGY_MANAGED_HOST_LISTENER_GENERATION`. Effigy verifies kernel ownership
and readiness before publication. Dependents receive current internal/public
URLs, state file and generation through `EFFIGY_MANAGED_HOST_<NAME>_*` and
restart on dependency endpoint/readiness changes. Failed-generation
diagnostics describe report, ownership, HTTP readiness and publication phases;
they are not ownership authority.

The bundle's opt-in Rust adapter passes the bind preference into the actual
Rust task, discovers its descendant's loopback listener and reports the actual
address. The Vite adapter loads the application's installed configuration,
strictly binds its managed loopback address, consumes the current API public
URL, and sets browser/HMR URLs including the gateway's actual HTTPS port.
Effigy owns their lifecycle; these adapters introduce no allocator or cache
manager. They are not connected to the bundle's default `dev` selector.

`scripts/dev/sveltekit-public-origin.mjs` supplies an explicit development hook
wrapper for an HTTP Vite listener behind an HTTPS gateway. A consumer opts in
through SvelteKit's supported `kit.files.hooks.server` setting. The disposable
Reference wrapper imports/chains its original `handle` and re-exports the
original hooks, including `handleError`. It is disabled outside development
or without the explicit profile flag. The configured HTTPS origin is fixed;
Host, forwarded context and unsafe request Origin are validated against it.
The wrapper presents coherent `event.url` and `event.request.url`, retaining
path/query, method, headers, cookies and the unread body stream. Its narrowly
scoped readiness path permits Effigy's host-only authority for safe local
readiness probes. It does not widen CSRF/CORS or change the upstream transport.

Private gateway mode requires a canonical caller-owned mode-0700 root via
`EFFIGY_GATEWAY_PRIVATE_STATE_ROOT` and explicit `--private-state-root`.
Certificates/CA remain in that root without trust installation, resolver,
alias or global gateway changes. Proof clients verify the fixture CA, actual
registered certificate/SAN, explicit SNI/name resolution and reported HTTPS
port.

## Reference pilot assurance and limits

Underlay Reference is the designated disposable pilot. Its operator checkout
and live stack remain untouched. Acowtancy testing or adoption is excluded
until qualification and a later explicit adoption ruling. No consumer default
switch is delivered here.

The executable runtime proof uses a clean Reference source checkout (qualified
commit `fa6a5e89ad83db460a5506b7fa3f915fa767d72a`), a private main clone and two
private worktrees. It assembles this bundle branch with
`sources.siblings = false`. Fixture-only app/config overrides exercise actual
Reference Rust API and front/admin Vite/SvelteKit applications. The hybrid
fixture excludes the workspace image and keeps host/Linux artifacts separate.

The proof establishes nine simultaneous distinct ready application listeners
and routes across those three identities. All three reach real isolated
Postgres, Mailpit and MinIO over loopback. Verified private HTTPS route probes
return the configured public origin in both SvelteKit URL surfaces, preserving
path/query; front and admin HMR WebSockets upgrade with 101. An owned ready API
restart changes endpoint/generation and route target, and restarts both
dependents with the current API URL. Occupied-port launch fails strictly before
publication while another instance's listener/route survives. A controlled
startup interruption records owned readiness 503, reconciles through exact
scope down, and recovers without signaling uncertain process identities.
Teardown of one worktree withdraws its sockets/routes while both other
instances continue serving.

The MinIO fixture builds the catalog's exact server release
`RELEASE.2025-09-07T16-13-09Z` / commit
`07c3a429bfed433e49018cb0f78a52145d4bedeb`, with real mc
`RELEASE.2025-08-13T08-35-41Z` / commit
`7394ce0dd2a80935aded936b09fa12cbb3cb8096`, verified prepared source archives,
Go 1.24.6, digest-pinned build/runtime bases and isolated build caches. It
verifies modules, versions and executable/image hashes. Protocol proof covers
readiness, signed S3 bucket/object PUT/GET/DELETE and exact-origin CORS. The
fixture image is local to the private runtime; shared catalog/default pins
remain unchanged.

Container-only assembly/build/start preserves the `workspace-rust-bun` image
and default 41001/41002/41003 inputs. It succeeds with the disclosed
fixture-local same-source MinIO image override. The published `minio/minio`
image pull remains unavailable in gathered evidence (`insufficient_scope`);
this local build does not repair registry access or certify that published
default image. A default consumer rollout therefore still needs that catalog
image precondition resolved. This PR qualifies opt-in fixture mechanisms, not
a released hybrid/dev:test selector or a consumer migration.

Cleanup stops/reconciles each exact host/container scope and verifies recorded
process identities, socket closure and route withdrawal while the runtime
profile exists. Worktree retire removes their scope records; the main
checkout returns an empty idempotent `scope = null` receipt, which is accepted
only after independent exact-scope reconciliation. Retirement alone is never
host cleanup evidence. After zero runtime environments/routes are confirmed,
the private gateway stops and the run-owned profile purges with `exists =
false`. Interrupted readiness diagnostics remain retained even after ownership
fields clear. Earlier uncertain records/residue are not reclaimed by these
proofs; the cause of the historical unavailable Reference generation remains
unestablished.

Local assurance is macOS host plus Linux containers. It does not establish a
local Linux Reference host proof or dedicated grace-to-SIGKILL end-to-end
coverage. Review/CI and any consumer migration remain separate gates.

## Qualification selectors

Set `UNDERLAY_PROFILE_EFFIGY_SOURCE`, `UNDERLAY_PROFILE_EFFIGY_BIN` and
`UNDERLAY_REFERENCE_SOURCE` explicitly. The repository owns these selectors:

- `proof:dev-profiles`: supporting synthetic binding/identity proof.
- `proof:dev-profiles:reference`: disposable Reference assembly/configuration
  and actual adapter plans; it does not launch applications.
- `proof:dev-profiles:public-origin`: helper security, opt-out, hook chaining
  and request/body preservation tests with bounded runner lifetime.
- `proof:dev-profiles:reference-runtime`: real three-instance applications,
  source-built MinIO, HTTPS/HMR and lifecycle proof with owned teardown.
- `proof:dev-profiles:reference-container`: independent container-only
  assembly/build/start with the disclosed same-source MinIO override.

Runtime selectors create fresh private roots and retain redacted receipts
outside the repository. Their source builder reads the prepared pinned source
packet from the local release-audits directory; missing or changed inputs fail
closed. No selector implicitly selects the global Effigy executable.
