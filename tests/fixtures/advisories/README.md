# Recorded advisory data

A workspace locking jinja2 3.1.2 from conda-forge and urllib3 1.26.4 from PyPI, and the pixi-policy cache a live
`pixi policy check` with `[advisories]` and `epss` wrote for it on 2026-10-14, so `tests/advisories.rs` runs offline
(`PIXI_POLICY_CACHE_DIR=cache`, `PIXI_POLICY_OFFLINE=1`).

- `pixi.lock` is `pixi lock`'s, with jinja2's `purls:` removed, as pixi writes it in a workspace without PyPI
  dependencies, so the conda-forge mapping has a package to name.
- `cache/advisories/osv/` is OSV's answers and records as fetched.
- `cache/advisories/kev.json` is CISA's catalog cut to its first three entries, none of which is about these packages.
- `cache/advisories/pypi-mapping.json` is conda-forge's mapping cut to the packages in `pixi.lock`.
- `cache/advisories/epss.json` is FIRST's scores for the CVEs found.

To record it again, delete `cache`, run the check online with `PIXI_POLICY_CACHE_DIR` pointing here, cut the catalog and
the mapping again, and update the counts in `tests/advisories.rs`.
