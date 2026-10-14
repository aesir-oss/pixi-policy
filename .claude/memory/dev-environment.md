---
name: dev-environment
description: Local quirks for working on pixi-policy: the Stop hook, pre-commit through pixi, miette wrapping, trying a local build
metadata:
  type: project
---

- The Stop hook is `.claude/hooks/stop-ci.sh`: it fingerprints HEAD, the diff and untracked files, skips when the
  fingerprint last passed, and exits 2 with the log tail on failure. If a stop is blocked, read `.pixi/.last-ci.log`,
  fix, and stop again; never touch `.pixi/.last-ci-ok`. The global Stop hook yields to a project-defined one.
- Local pre-commit hooks call `pixi run <tool>` because the git hook runs outside the pixi env.
- miette wraps error text at 80 columns by default; keep wrapping off so lists of names in errors stay greppable.
- To try a local build as `pixi policy`, put `target/release` first on PATH in that terminal; never copy a binary
  into `~/.pixi/bin` (its launchers are hard links shared by every pixi global command).

**Why:** environment facts not derivable from the code; carried over from pixi-ext-contrib, where they were learned.

**How to apply:** use when a stop is blocked or when testing the binary by hand. Related: [[concurrent-ci-runs]].
