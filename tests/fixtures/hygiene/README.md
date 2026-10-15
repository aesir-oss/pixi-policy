# hygiene fixture

`pixi.lock` was written by `pixi lock` from `pixi.toml` and then edited by hand, because pixi itself does not install a
PyPI package that a conda package's purls say it already has:

- PyPI `msgpack` 1.1.2 was added beside conda `msgpack-python`, whose purls say it provides PyPI `msgpack`: a
  duplicate whose names differ.
- The `purls` of conda `pyyaml` were removed, and PyPI `pyyaml` 6.0.3 added: a duplicate only conda-forge's mapping
  shows (`cache/advisories/pypi-mapping.json`, a few entries of it).
- PyPI `six` has no conda counterpart.
