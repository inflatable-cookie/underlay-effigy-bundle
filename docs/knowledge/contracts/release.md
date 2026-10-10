# Release

There are no tags or versions. Consumers reference the bundle by Git URL with
no pinned ref, so a merge to `main` is a release to every consumer at once.

## Consumer ref policy

Consumers retain `main` tracking. The operator's ruling on 2026-10-10 is:
"Retain main tracking; revisit on concrete hold-back, regression or
reproducibility need."

Recheck this policy when a consumer needs to hold a known-good bundle while
another upgrades, a `main` update causes a consumer regression, or reconstructing
a CI or development environment requires an exact bundle commit. The reporting
consumer's planner and the bundle owner collect the concrete evidence.

Immutable commit-pin adoption requires separate planning: prove update and
rollback in disposable consumer fixtures, inspect current consumer refs and
affected child catalogs, and establish upgrade ownership before consumer changes.
The ruling preserves the shared rollback below.

## Steps

1. Keep the change backward-compatible: new inputs get safe defaults. If it
   needs a newer Effigy, raise `minimum_effigy_version` in `export.toml` in the
   same change.
2. Before merging, assemble it from a consumer: point a consumer checkout's
   `[bundle]` at the branch, run its container build and plan (for example
   `effigy container up`), and confirm that the stack starts and the default
   inputs behave as before.
3. Update `README.md` for any new or changed input.
4. Merge to `main`. Tell the consuming repositories' planners when the change
   needs action from them, such as an image rebuild.

## Verify

- A consumer on default inputs sees no change.
- A consumer opting into a new input sees the documented effect.
- A consumer with `sources.siblings = false` resolves bundle tasks without
  sibling catalogs or checkout paths.

## Roll back

Revert the merge on `main`. Consumers pick up the revert on their next run.
Anything a consumer rebuilt, such as a workspace image, may need rebuilding
again.
