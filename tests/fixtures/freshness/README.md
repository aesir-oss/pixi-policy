# Recorded channel data

A workspace locking setuptools 59.8.0, jinja2 2.11.3, coreapi and their dependencies from conda-forge for linux-64,
and the pixi-policy cache a live `pixi policy check` with `max-build-age-days`, `max-majors-behind` and `archived` wrote
for it on 2026-10-14, so `tests/freshness.rs` runs offline (`PIXI_POLICY_CACHE_DIR=cache`, `PIXI_POLICY_OFFLINE=1`).

- `cache/freshness/repodata/*/repodata_shards.msgpack.zst` is conda.anaconda.org's shard index for linux-64 and noarch,
  cut to the packages in `pixi.lock` and recompressed.
- `cache/freshness/shards/` is the shards as fetched.
- `cache/freshness/feedstocks.json` and `feedstock-outputs.json` are the conda-forge bot's lists cut to the feedstocks
  and packages of `pixi.lock`.

To record it again, delete `cache`, run the check online with `PIXI_POLICY_CACHE_DIR` pointing here, cut the indexes and
lists again, and update the versions in `tests/freshness.rs`.
