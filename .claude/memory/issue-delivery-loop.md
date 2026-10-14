---
name: issue-delivery-loop
description: "pixi-policy specifics for the standard guardrail/harness (issue delivery loop), which itself lives in global CLAUDE.md §6"
metadata:
  type: feedback
---

The "standard guardrail" / "harness" (branch, CI, PR, monitor to green, merge, sync main, clean branches, then the
next queued issue) is defined in global CLAUDE.md §6 "Issue delivery loop". Follow that.

aesir-oss/pixi-policy specifics on top of it (the working clone is the fork millsks/aesir-pixi-policy: `origin` is the
fork, `upstream` is aesir-oss/pixi-policy; branches are pushed to the fork and PRs opened against upstream, whose
CI runs on them, and the fork keeps Actions off; sync with `git pull --ff-only upstream main`):

- merge with `gh pr merge <n> --repo aesir-oss/pixi-policy --squash --admin --delete-branch` (squash is the
  convention; `--admin` because `main`'s ruleset wants an approving review)
- PR bodies state what was measured, not just what changed
- gate the merge on the checks' result, counted after the watch ends: merge only when no check is non-passing. Never
  chain the merge after `gh pr checks --watch` in one command; in aesir-oss/pixi-ext-contrib that merged PR #107 with
  cargo-deny red.
- merging a PR that touches `.github/workflows/` needs the `gh` token's `workflow` scope
  (`gh auth refresh -s workflow`); without it the merge fails with "refusing to allow an OAuth App to create or update
  workflow". Pushing over SSH does not need it, so the gap only shows at merge. Confirm the PR is `MERGED` before
  deleting any branch: on 2026-10-13 cleanup chained after a failed merge deleted #33's head, closing the PR
  (restored from the local sha and reopened)
- the release Build matrix runs on `main` only, so a green PR can still turn `main` red: after every merge, watch
  `main`'s CI run to the end before starting the next issue
- `pixi run ci` does not run cargo-deny; CI's `deny` job does. A change to `Cargo.toml` dependencies or `deny.toml`
  gets `pixi run -e lint deny` locally before the PR.

**Why:** the maintainer gave standing permission to run queued issues without re-asking, and made the loop their
standard across all projects.

**How to apply:** treat "guardrail" or "harness" in a request as meaning that loop. Cutting a release is never part
of it: ask first, every time.

Related: [[releases]], [[split-from-pixi-ext-contrib]].
