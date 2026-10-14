---
name: action-and-hooks-repos
description: "The pixi-policy Action and pre-commit hooks ship from generated repos aesir-oss/pixi-policy-action and -pre-commit, the pixi-sbom way"
metadata:
  type: project
---

pixi-sbom's Action lives in its repository and a release job copies it to `aesir-oss/pixi-sbom-action` (tags
`vX.Y.Z`, moves `vX`, creates a release on each final); its hooks go to `aesir-oss/pixi-sbom-pre-commit`. pixi-policy
gets the same shape: `actions/pixi-policy/` (#4) is copied to `aesir-oss/pixi-policy-action` on every release, and
`pre-commit-mirror/` (#5) is rendered into `aesir-oss/pixi-policy-pre-commit` on finals only, after the PyPI upload (a
release candidate's wheel is on TestPyPI, which the hook's pip never reads). Both jobs `git clone` rather than
`actions/checkout`, which fails on the still-empty repositories. #15 adds the action's GitHub Release.

**Why:** the Marketplace lists one action per repository, with `action.yml` at its root, and lists from releases,
not tags. Action names are unique on the Marketplace.

**How to apply:** check the name `pixi-policy` is free on the Marketplace before the first listing. Ticking "Publish
this Action to the GitHub Marketplace" is a manual step on the first final's release (no API); after that the
workflow-created release keeps the listing current (confirmed for pixi-sbom at 1.14.0). Never resolve
`releases/latest` in the Action; name the tag. Related: [[releases]], [[roadmap]].
