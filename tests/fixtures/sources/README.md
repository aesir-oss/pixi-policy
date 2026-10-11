A hand-written `pixi.lock` with one package from every kind of source, for the `sources` rules (#61): channels by
name (anaconda.org and prefix.dev spellings), by URL and a disallowed one; PyPI from the default index, an internal
index and a disallowed one; and git, URL and path packages, both conda (pixi-build) and PyPI. `.pixi/config.toml`
mirrors conda-forge: mirrors only change where pixi downloads from, so `pixi.lock` still names conda-forge.
