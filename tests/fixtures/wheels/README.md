# wheels fixture

`cache/wheel-info/<sha256>/METADATA` is each PyPI wheel's METADATA in examples/projects/pixi/02-flask, recorded from
pypi.org by `pixi policy check` (with `[licenses]`) run online with `PIXI_POLICY_CACHE_DIR` pointing here. The
directory names are the wheels' sha256 from that workspace's pixi.lock, so tests/wheels.rs reads them offline.
