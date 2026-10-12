Manifests for the `manifest.*` rules (#64): `pass/` satisfies every rule under `required-platforms = ["linux-64",
"osx-arm64", "win-64"]`; `fail/` breaks each one (a `*` conda, PyPI and feature dependency, an unpinned Python, two
missing platforms). The tests read the manifests only, so there is no lockfile.
