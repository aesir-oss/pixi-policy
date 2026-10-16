---
name: roadmap
description: "pixi-policy release history and what each milestone holds; 0.3.0 milestone empty 2026-10-16, rc.1 next"
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
  builds). #15 closed once the Marketplace listing existed; #17 closed when the feedstock's bot PR for 0.2.0 merged
  (the feedstock now has `bot.automerge: true`).
- Milestone 0.3.0, every issue merged 2026-10-15/16, released from 0.3.0-rc.1 on: #42 `[python]` standard version,
  #44 `[freshness]` missing from `keys::TABLES`, #11 `[hygiene]` conda/PyPI duplicates, #7 license spellings and
  `licenses.ambiguous`, #10 VEX in `[advisories]`, #9 `pixi policy facts` with a Rego example (`-e rego`, opa); then
  #58 the cache under pixi's cache dir, #51 PyPI licenses from wheel METADATA (miniz_oxide added), #52 PyPI freshness,
  #57 KEV counts as critical, #56 `python.requires-python`, #55 `manifest.exclude-newer`, #54 `pixi policy lock`,
  #53 `init` proposes the newer tables, #60 review verdict for `OR`. Steps 26 onward of the field-test checklist
  cover them.
- #8 provenance moved to 1.0.0: no channel serves CEP 27 `.sigs` yet, and the verifiers need aws-lc-rs (see the
  issue). Milestone 1.0.0 also holds #12 the stability contract.
- #13 (RUSTSEC-2024-0449, `unsafe-libyaml` via rattler's `serde_yaml`) has no milestone: blocked on rattler; the
  `deny.toml` ignore points at it.
- pixi-sbom's `--deny-license` deprecation (aesir-oss/pixi-sbom, formerly pixi-ext-contrib#85) waited for pixi-policy
  to exist, since pixi-policy takes over the license gate.

**Why:** the plan was written in pixi-ext-contrib, whose roadmap memory is mostly pixi-sbom history.

**How to apply:** update this after each release; the issues themselves are the source of truth. Related:
[[releases]], [[action-and-hooks-repos]].
