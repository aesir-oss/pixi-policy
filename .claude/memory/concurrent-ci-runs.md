---
name: concurrent-ci-runs
description: "Overlapping `pixi run ci` runs (mine, the Stop hook's, another session's) SIGKILL each other's test binaries on macOS; not a test failure"
metadata:
  type: project
---

`pixi run ci` failing with `signal: 9, SIGKILL: kill` on a test binary, or a `NotFoundError` for a binary under
`target/llvm-cov-target`, with no test reported failing, means two CI runs overlapped. Both use
`target/llvm-cov-target`; when one rebuilds a test binary while the other runs it, macOS kills the running process
because its code signature no longer matches the file. The other run may be the Stop hook (`.claude/hooks/stop-ci.sh`)
or a different Claude session's hook in the same working tree. Seen repeatedly in pixi-ext-contrib (2026-10-09/10).

Another session's uncommitted work in the shared tree can also make the hook fail in a session that changed nothing.

**Why:** it looks like a flaky test and invites a pointless "fix".

**How to apply:** on a sudden mass failure, check `pgrep -f "cargo-llvm-cov llvm-cov"` and `ListAgents` before
debugging; wait for the other run and rerun alone. If the other keeps restarting, give yours its own dir:
`CARGO_LLVM_COV_TARGET_DIR=$PWD/target/llvm-cov-<issue> pixi run ci`. Never run `pixi run ci` in the background while
a turn may end (the hook starts another), and never edit another session's files to make the hook pass.
Related: [[issue-delivery-loop]], [[dev-environment]].
