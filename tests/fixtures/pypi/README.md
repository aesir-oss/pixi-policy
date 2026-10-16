# pypi fixture

`cache/freshness/pypi/<name>.json` is what `[freshness] pypi` keeps of PyPI's JSON API (`/pypi/<name>/json`) for each
PyPI package in examples/projects/pixi/02-flask: the newest release that is neither a prerelease nor yanked, and each
file's upload time by sha256. Recorded from pypi.org on 2026-10-15 by `pixi policy check` run online with
`PIXI_POLICY_CACHE_DIR` pointing here; tests/pypi_freshness.rs reads it offline.
