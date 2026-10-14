# Development

pixi-policy is one Rust crate. Everything runs through [pixi](https://pixi.sh), which pins the toolchain in
`pixi.lock`, so a checkout builds the same way on every machine and in CI.

```sh
pixi run test   # unit and end-to-end tests
pixi run ci     # the full gate: pre-commit, release build, check, clippy, coverage >= 90%
```

## Tasks

| Task | What it does |
|---|---|
| `test` | `cargo test`: the unit tests beside the code and the end-to-end tests in `tests/` |
| `lint` | `cargo clippy --all-targets -- -D warnings` |
| `check`, `fmt`, `build` | `cargo check`, `cargo fmt`, the release build |
| `cov` | coverage with `cargo llvm-cov`, failing under 90% of lines |
| `ci` | `pre-commit-run`, `build`, `check`, `lint` and `cov`: what must pass before a change is done |
| `policy-docs` | regenerate [the policy reference](reference.md) and [the rule catalog](rules.md) from the code |
| `-e lint deny` | `cargo deny check`: advisories, licenses, banned crates and sources, against `deny.toml` |
| `-e msrv msrv-check` | `cargo check` on the oldest toolchain `Cargo.toml` claims |
| `-e docs docs-serve`, `-e docs docs-build` | this site, served with live reload or built strictly |

`pixi run bootstrap` installs the pre-commit hooks once per clone.

## Layout

| Path | What it is |
|---|---|
| `src/main.rs`, `src/cli.rs` | the command line |
| `src/check.rs`, `src/rules/` | the rule engine and one module per rule family |
| `src/policy.rs`, `src/keys.rs` | the policy file's parser, and every key it accepts with its type, values and default |
| `src/lockfile.rs`, `src/manifest.rs`, `src/workspace.rs` | reading `pixi.lock` and `pixi.toml` |
| `src/license.rs`, `src/license_policy.rs`, `src/purl.rs` | license normalisation, the license verdict, package URLs |
| `src/report.rs`, `src/style.rs`, `src/pipe.rs` | text, JSON and SARIF reports; terminal colour; output a reader may close early |
| `src/explain.rs`, `src/waivers.rs`, `src/init.rs` | `explain`, waivers that expire, `init` |
| `schemas/` | the JSON report's schema, published with the docs |
| `actions/pixi-policy/` | the GitHub Action, copied to `aesir-oss/pixi-policy-action` on each release |
| `pre-commit-mirror/` | the pre-commit hook, rendered into `aesir-oss/pixi-policy-pre-commit` on each final |
| `tests/` | end-to-end tests of the binary, with fixtures and schemas |
| `examples/projects/pixi/` | 19 real pixi workspaces the tests and the field test run against |
| `docs/`, `mkdocs.yml` | this site |

The license, lockfile, purl, style and pipe modules began in a crate pixi-policy shared with pixi-sbom in
[aesir-oss/pixi-ext-contrib](https://github.com/aesir-oss/pixi-ext-contrib). Since this repository was split out,
they are pixi-policy's own and change with its needs.

## Generated pages

[The policy reference](reference.md) and [the rule catalog](rules.md) are generated from `src/keys.rs` and the text
`pixi policy explain` prints. `tests/docs.rs` fails when either page differs from the code, and `src/keys.rs` has
tests that fail when the policy parser accepts a key the reference does not list, or the reference lists one the
parser rejects. Change the code, then run `pixi run policy-docs`.

## Releases

A release starts from the **Release** workflow (`workflow_dispatch`, with a `version`). It refuses to run unless
`main`'s CI passed on the commit, then bumps the version in `Cargo.toml`, `Cargo.lock` and `pixi.toml`, adds the
release's section to `CHANGELOG.md` with git-cliff, commits, and pushes the tag `vX.Y.Z`. The tag starts
**Release artifacts**, which builds the wheels and the five archives (`pixi-policy-vX.Y.Z-<platform>`), signs their
provenance, publishes the GitHub release, and uploads the wheels: to TestPyPI for a release candidate
(`0.1.1-rc.1`), to PyPI for a final. Publishing the release redeploys this site under the version.

- Never bump versions or push tags by hand: a pushed `v*` tag starts a release.
- Never edit `CHANGELOG.md`'s existing sections. Each release adds its own on top; those up to 0.1.0 were written in
  aesir-oss/pixi-ext-contrib and link there.
- Every release candidate goes through a field test of the published files before a final is cut.

The same run fills two generated repositories with the release App, which must be installed on both:

- `aesir-oss/pixi-policy-action` gets `actions/pixi-policy/` on every release, tagged `vX.Y.Z`. A final also moves
  `vX` when it is the newest release of its major, and gets a GitHub release, marked Latest when `vX` moved: the
  Marketplace lists the action from releases, not tags.
- `aesir-oss/pixi-policy-pre-commit` gets the hook rendered for the version, tagged `vX.Y.Z`, on finals only and after
  the PyPI upload, since the hook installs the wheel from PyPI.

The Marketplace listing itself is a manual step, once: GitHub has no API for it. On the first final's release in
`aesir-oss/pixi-policy-action`, choose **Edit**, tick **Publish this Action to the GitHub Marketplace** (an
aesir-oss owner may first have to accept the Marketplace Developer Agreement), pick the categories **Security** and
**Continuous integration**, and update the release. The listing is
[marketplace/actions/pixi-policy](https://github.com/marketplace/actions/pixi-policy).
