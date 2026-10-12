# CLAUDE.md

Project guidance for aesir-oss/pixi-policy. The global CLAUDE.md (toolchain, harness, git workflow) applies; this
file covers what is specific here. This project is **Rust**: the Python-specific parts of the global file (mypy,
pytest, structlog) do not apply.

@.claude/memory/MEMORY.md

## Architecture

One crate, `pixi-policy`, a binary pixi runs as `pixi policy`: it checks a workspace's `pixi.toml` and `pixi.lock`
against `pixi-policy.toml`. See [docs/development.md](docs/development.md) for the module layout.

| Path | What it is |
|---|---|
| `src/` | the crate; `src/rules/` holds one module per rule family |
| `tests/` | end-to-end tests of the binary, with fixtures and schemas; `tests/docs.rs` checks the generated pages |
| `schemas/` | the JSON report's schema, published with the docs |
| `examples/projects/pixi/` | 19 pixi workspaces the tests and the field test run against |
| `docs/`, `mkdocs.yml` | the docs site (MkDocs Material, versioned with mike) at aesir-oss.github.io/pixi-policy |
| `pyproject.toml` | maturin `bindings = "bin"`: the binary as platform wheels for PyPI |

## Commands

Everything runs through pixi.

| Task | Command |
|---|---|
| Format, lint, check | `pixi run fmt`, `pixi run lint` (clippy `-D warnings`), `pixi run check` |
| Tests | `pixi run test`; one test: `pixi run cargo test --test cli <name>` |
| Full gate | `pixi run ci` (pre-commit, build, check, clippy, coverage ≥ 90%); the Stop hook runs it |
| Generated docs pages | `pixi run policy-docs` after changing `src/keys.rs` or the explain text |
| Docs | `pixi run -e docs docs-build` (strict), `pixi run -e docs docs-serve` |
| Dependencies | `pixi run -e lint deny` |

## Releases

- Started by the Release workflow (`workflow_dispatch`, `version` input). It bumps the version, adds the release's
  section to `CHANGELOG.md`, commits and tags `vX.Y.Z` with the release App; the tag starts `release-artifacts.yml`.
- Release candidates go to TestPyPI, finals to PyPI, with trusted publishing. Ask before cutting any release.

## Off-limits and traps

- Never bump versions or push tags by hand. A pushed `v*` tag starts a release.
- `CHANGELOG.md`'s existing sections are never edited or regenerated; each release adds its own on top.
- `docs/reference.md` and `docs/rules.md` are generated: change the code and run `pixi run policy-docs`.
- `gh-pages` holds the built docs site; never merge it anywhere.
- `.claude/memory/` is public. Nothing private, personal or about the maintainer's employer goes in it.
