---
name: roadmap
description: "pixi-policy release history and what each milestone holds, as of 2026-10-15"
metadata:
  type: project
---

- 0.1.0 (rc.1 to rc.3, then final) was released from pixi-ext-contrib on 2026-10-12: `pixi policy check`, the
  sources, bans, licenses, manifest and lock hygiene rules, expiring waivers, text/JSON/SARIF output, `init` and
  `explain`, the docs site and PyPI. See [[split-from-pixi-ext-contrib]].
- 0.1.1 (rc.1 the same day) was the first release from this repository, with no behaviour change.
- 0.2.0 (rc.1 and rc.2 on 2026-10-14, final 2026-10-15): #1 extends (paths and pinned URLs, `show --resolved`),
  #2 freshness, #3 advisories, #4 the Action, #5 the pre-commit hook, #15 Action releases, #18 SARIF links. rc.2 only
  trimmed advisory summaries (#40, found by rc.1's field test). The first build with ring, ruzstd and rmp-serde: all
  seven wheels built. #6 closed (conda-forge/pixi-policy-feedstock, all five platforms after its PR #1 added the ARM
  builds). Still open: #15 for the manual Marketplace listing of pixi-policy-action v0.2.0, #17 until the feedstock's
  version bot opens 0.2.0's PR on its own.
- Milestone 0.3.0: #7 SPDX normalisation, #8 provenance, #9 OPA/Rego export, #10 VEX-aware advisories, #11 the same
  package from conda and PyPI. Milestone 1.0.0: #12 the stability contract.
- #13 (RUSTSEC-2024-0449, `unsafe-libyaml` via rattler's `serde_yaml`) has no milestone: blocked on rattler; the
  `deny.toml` ignore points at it.
- pixi-sbom's `--deny-license` deprecation (aesir-oss/pixi-sbom, formerly pixi-ext-contrib#85) waited for pixi-policy
  to exist, since pixi-policy takes over the license gate.

**Why:** the plan was written in pixi-ext-contrib, whose roadmap memory is mostly pixi-sbom history.

**How to apply:** update this after each release; the issues themselves are the source of truth. Related:
[[releases]], [[action-and-hooks-repos]].
