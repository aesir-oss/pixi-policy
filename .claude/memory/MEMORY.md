Project memory for aesir-oss/pixi-policy. Committed and public: nothing private or employer-related belongs here.

- [Issue delivery loop](issue-delivery-loop.md) — "guardrail"/"harness" = global CLAUDE.md §6 loop; merge with --squash --admin --delete-branch; never cut a release unasked
- [Releases](releases.md) — vX.Y.Z tags, rc to TestPyPI and final to PyPI, field test after every rc, changelog sections prepended
- [Split from pixi-ext-contrib](split-from-pixi-ext-contrib.md) — where the history, the 0.1.0 releases and the once-shared modules came from
- [Force-push permission](force-push-permission.md) — own feature branches, and the stale-check trap behind it
- [Roadmap](roadmap.md) — releases so far (0.2.0 final 2026-10-15) and what milestones 0.3.0 and 1.0.0 hold
- [Concurrent CI runs](concurrent-ci-runs.md) — SIGKILL in cov = two ci runs overlapping (mine, the Stop hook, another session), not a failing test
- [Dev environment](dev-environment.md) — the Stop hook, pre-commit through pixi, miette wrapping, trying a local build via PATH
- [Release binaries](release-binaries.md) — archives carry the manylinux wheel's binary (glibc 2.17); nothing on crates.io
- [Action and hooks repos](action-and-hooks-repos.md) — aesir-oss/pixi-policy-action and -pre-commit, filled by release jobs; Marketplace listing is manual once
- [Network layer](network-layer.md) — ureq on rustls/ring + platform verifier, sha2 0.11, the extends, advisories and freshness caches; watch the wheel builds when a C dependency changes
