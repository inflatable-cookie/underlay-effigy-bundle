# Questions

Questions that block or shape work. Reference them by ID from the plan and from
briefs. An answered question keeps only its pointer to where the answer lives.

## Q-001 — Should consumers pin a bundle ref?

Status: open
Context: consumers reference the bundle by Git URL with no ref, so every merge
to `main` reaches all of them at once. Pinning a tag or commit would make
bundle changes an explicit upgrade in each consumer.
