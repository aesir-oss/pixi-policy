---
name: releases
description: "How pixi-policy releases: tags vX.Y.Z, rc to TestPyPI and final to PyPI, a field test after every rc, changelog sections prepended and never regenerated"
metadata:
  type: project
---

- Releases start from the Release workflow (`version` input) and are tagged `vX.Y.Z`; the tag starts Release
  artifacts. Archives are `pixi-policy-vX.Y.Z-<platform>`, with provenance attestations signed by this repository's
  `release-artifacts.yml`.
- A release candidate (`0.1.1-rc.1`) is a GitHub pre-release and goes to TestPyPI; a final goes to PyPI and is this
  repository's Latest release. The docs deploy under the version; a final also moves `latest`.
- After every release candidate the maintainer's field-test checklist is run against the published files before a
  final is cut. Ask before cutting any release.
- `CHANGELOG.md`: each release adds its section below the header (`scripts/changelog.sh`, run by the Release
  workflow). Existing sections are never regenerated, so never edit them or regenerate the file.
- conda-forge builds from the `v*` source tarballs; the feedstock's bot follows new tags.

Related: [[issue-delivery-loop]], [[split-from-pixi-ext-contrib]].
