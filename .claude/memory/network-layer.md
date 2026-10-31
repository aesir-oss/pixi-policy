---
name: network-layer
description: "pixi-policy's network use: extends URLs (#1), advisories (#3) and freshness (#2) via ureq on rustls/ring with the platform verifier, cached; what to watch when a C dependency changes"
metadata:
  type: project
---

Added 2026-10-14 for #1's URL half (maintainer approved the two runtime dependencies): `ureq` 3 with
`default-features = false, features = ["rustls", "platform-verifier"]` (rustls on `ring`, no aws-lc, system certificate
store, proxies from `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` and `NO_PROXY`), and `sha2` 0.11, the version rattler already
pulls in, so there is no second copy. `src/fetch.rs` holds the fetch and the cache; `PIXI_POLICY_CACHE_DIR` and
`PIXI_POLICY_OFFLINE` steer it, and tests pass a `Settings` value rather than set env vars (process-global, racy).

#3 (advisories) added `src/advisories.rs` on the same agent (`fetch::get`, `fetch::post_json`): OSV, CISA KEV, FIRST
EPSS and the conda-forge mapping, ported from pixi-sbom's osv/kev/epss/mapping/cvss modules (copies; nothing keeps
them in step). It caches under `<cache>/advisories/` and fails closed (`advisories.unavailable`) when it has no data.
Its `Client` trait lets unit tests answer for the network; `tests/advisories.rs` runs offline on the recorded cache in
`tests/fixtures/advisories/` (its README says how to re-record it).

#2 (freshness) added `src/freshness.rs`: CEP-16 sharded repodata from each package's own channel URL (anaconda.org
gives an empty `shards_base_url`, meaning beside the index), the whole `repodata.json(.zst)` for channels without
shards, the package's subdir and noarch combined; plus the conda-forge bot's `all_feedstocks.json` and
feedstock-outputs for archived feedstocks (chosen over the GitHub API: no token, no rate limit; it trails GitHub by a
bot cycle, documented). Added `ruzstd` and `rmp-serde` (pure Rust) with approval. Fixture: `tests/fixtures/freshness/`.

0.3.0 added more on the same agent: #10 VEX files by pinned URL through the extends cache; #51 `fetch::get_tail` and
`get_range` with `src/zipread.rs` (pixi-sbom's, deflate by `miniz_oxide`, already in the tree via miette) to read a
wheel's METADATA by range, cached at `<cache>/wheel-info/<sha256>/`; #52 PyPI's JSON API for freshness, cached a day
reduced to the newest release and upload times. #58 moved the cache to `pixi-policy/` under pixi's cache directory
(`PIXI_CACHE_DIR`, `RATTLER_CACHE_DIR`, then the platform cache's `rattler/cache`), beside pixi-sbom's. Tests that
check with `[licenses]` run offline with an empty cache so they never reach PyPI.

0.4.0: on 2026-10-31 the feedstock list's home, `regro/cf-graph-countyfair`, was gone (404). The bot now publishes the
same file at `conda-forge/conda-forge-bot-data` (`main`). Until #82 moved the default, every `[freshness]` check with
conda-forge packages failed. #84 made each freshness source fail on its own. `fetch::probe` (#76) classifies a failed
request by layer (DNS, proxy, TLS, timeout, connection) for `pixi policy doctor`, which found #82. Run the doctor when a
fetch-based family reports `*.unavailable`; it names the upstream that is down.

**Why:** pixi-sbom kept the "shared network stack" at the split, so this crate had none until #1.

**How to apply:** `ring` is the first C dependency here. The release wheels build from the tag, so a dry run cannot
exercise it: 0.2.0-rc.1 was the first release to build it, and all seven wheel jobs (musllinux and the macOS
x86-64 cross-build included) passed; keep watching them when a C dependency changes. Any new network feature (#2 freshness, #3 advisories) reuses `fetch.rs`'s agent
and cache. Related: [[release-binaries]], [[releases]].
