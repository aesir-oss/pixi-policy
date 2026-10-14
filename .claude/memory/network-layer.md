---
name: network-layer
description: "pixi-policy's only network use: extends URLs (#1) via ureq on rustls/ring with the platform verifier, cached; what to watch in the next rc"
metadata:
  type: project
---

Added 2026-10-14 for #1's URL half (maintainer approved the two runtime dependencies): `ureq` 3 with
`default-features = false, features = ["rustls", "platform-verifier"]` (rustls on `ring`, no aws-lc, system certificate
store, proxies from `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` and `NO_PROXY`), and `sha2` 0.11, the version rattler already
pulls in, so there is no second copy. `src/fetch.rs` holds the fetch and the cache; `PIXI_POLICY_CACHE_DIR` and
`PIXI_POLICY_OFFLINE` steer it, and tests pass a `Settings` value rather than set env vars (process-global, racy).

**Why:** pixi-sbom kept the "shared network stack" at the split, so this crate had none until #1.

**How to apply:** `ring` is the first C dependency here. The release wheels build from the tag, so a dry run cannot
exercise it: in the next release candidate, watch all seven wheel jobs (musllinux and the macOS x86-64 cross-build
especially) before the field test. Any new network feature (#2 freshness, #3 advisories) reuses `fetch.rs`'s agent
and cache. Related: [[release-binaries]], [[releases]].
