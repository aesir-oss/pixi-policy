---
name: release-binaries
description: "Release archives carry the PyPI wheel's binary (manylinux, glibc 2.17 floor); nothing goes to crates.io"
metadata:
  type: project
---

Decided in pixi-ext-contrib on 2026-10-11 and inherited by this repository:

- Every platform is compiled once, as its PyPI wheel (maturin, `bindings = "bin"`), and the release archive carries
  that wheel's binary (`release-artifacts.yml`). Linux archives use the manylinux binary, built against glibc 2.17,
  so they run on every glibc distribution from CentOS 7 / Amazon Linux 2 on; runner-built binaries needed 2.28.
- Nothing is published to crates.io (`publish = false`): conda-forge, PyPI and the archives build from this
  repository, and crates.io carried about 2% of pixi-sbom's downloads.

**Why:** one binary per platform for pip and archive users, and the widest Linux reach.

**How to apply:** do not go back to building Linux archives with `pixi run build` on the runner, or add a crates.io
publish, without revisiting this with the maintainer. Related: [[releases]].
