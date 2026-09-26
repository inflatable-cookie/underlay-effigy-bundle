# Release

There are no tags or versions. Consumers reference the bundle by Git URL with
no pinned ref, so a merge to `main` is a release to every consumer at once.

## Steps

1. Keep the change backward-compatible: new inputs get safe defaults. If it
   needs a newer Effigy, raise `minimum_effigy_version` in `bundle.toml` in the
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

## Roll back

Revert the merge on `main`. Consumers pick up the revert on their next run.
Anything a consumer rebuilt, such as a workspace image, may need rebuilding
again.
