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

## Qualification result — 2026-10-09

Effigy source checkout `94dd80a25b279408aa0dcf9b36a4c802b26a237e` and binary
`v0.14.1+local.7b26a15` were inspected. The binary commit is an ancestor of
the inspected source checkout. Its current mechanisms support container-owned
routes and isolated worktree domains; they do not qualify bundle-owned host
process routes.

- `container_lifecycle` starts and stops the task's selected container. The
  `health_wait` contract waits on routes owned by that container and does not
  probe a route targeting an external host process.
- Container routes are registered after matching Compose project/service
  ports are observed. `container hosts` derives distinct HTTPS domain names
  for linked worktrees while leaving the primary checkout's declared names.
- A route's `target_host = "host:port"` is an explicit static external target.
  The current route registration path skips both Compose binding validation
  and the host-listener collision check for that target. Its route ownership
  remains attached to the container environment, not to a managed host child.
- The installed Rhai `gateway` module exposes `down`, `setup_tls`, `status`,
  and `up`. It has no route publication or owned-listener registration call.

The bounded gap is a language-neutral Effigy ownership contract that connects
one managed host child to its actual listening endpoint. A bundle adapter must
be able to describe the child task, requested loopback binding, readiness
condition, and browser route. Effigy must associate the resulting address with
the checkout/runtime-generation/profile identity, prove readiness for that
child before publishing, replace the route after restart, reject a foreign
listener or hostname claim, and clean only the recorded child and route. If
ownership is uncertain, the claim must remain explicit. The bundle remains
responsible for Rust/Vite launch recipes, service URLs, browser origins and
HMR settings. This describes the missing contract; it is not an existing CLI
or script protocol.

`effigy proof:dev-profiles` assembles a private consumer from the bundle path
with `sources.siblings = false`, creates a private main checkout and two
worktrees, and starts real minimal Rust and Bun listeners at OS-assigned ports.
It checks that all six listeners work concurrently, that the worktrees receive
distinct HTTPS domain names, and that strict binding fails without disturbing
an occupied foreign listener. It inspects the default `dev` plan and leaves the
container runtime, gateway daemon, and macOS resolver untouched.

The required default container startup was attempted once from the private
consumer. Effigy generated the Compose plan but `container up` exited 1 during
TLS route setup: `mkcert -install` attempted to add a local CA to the macOS
trust store and was denied because the worker had no interactive
authorization. Effigy's scoped `container retire` exited 0, and a subsequent
read-only status showed no services. No gateway or resolver was started. The
selector now stops before that operation; this run does not certify default
stack startup or HTTPS connectivity.

These proofs do not certify hybrid or `dev:test`: no bundle or Effigy path in
this version connects the host children to owned gateway routes. Service
container reachability from host processes, SvelteKit origins, Vite HMR,
restart route replacement, interrupted owner recovery, and isolated host-route
teardown remain unavailable pending the Effigy ownership contract. The current
container `dev` task, inputs, and fixed default ports are unchanged. No README
or input-schema change is needed until an opt-in profile can be implemented on
supported interfaces.
