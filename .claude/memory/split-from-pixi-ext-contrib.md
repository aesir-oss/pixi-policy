---
name: split-from-pixi-ext-contrib
description: "pixi-policy was split out of the aesir-oss/pixi-ext-contrib monorepo on 2026-10-12: what came with it and what stayed behind"
metadata:
  type: project
---

pixi-policy was developed in the aesir-oss/pixi-ext-contrib Cargo workspace, beside pixi-sbom, and moved to this
repository in October 2026 (plan: aesir-oss/pixi-ext-contrib#131). Its history came with it (`git filter-repo`), so
commit messages reference that repository's issues and PRs by number.

- Releases 0.1.0-rc.1 to 0.1.0 were made there, tagged `pixi-policy-vX.Y.Z`; their tags are carried here as `vX.Y.Z`,
  but their GitHub releases, archives and attestations stay in pixi-ext-contrib, which is archived.
- The license, license_policy, lockfile, purl, pipe and style modules came from the crate pixi-policy shared with
  pixi-sbom. They are this crate's own now and may drift from pixi-sbom's copies; nothing keeps them in step.
- `examples/projects/pixi` is a copy of the monorepo's example workspaces, and `tests/fixtures/with-pypi` and
  `tests/schemas/sarif-schema-2.1.0.json` were pixi-sbom's.

**Why:** the maintainer wanted each extension in its own repository, so either can be handed to a new owner by
transferring one repository.

**How to apply:** links to aesir-oss/pixi-ext-contrib issues in old commits and the 0.1.0 changelog are history; do
not rewrite them. New issues and PRs live here.
