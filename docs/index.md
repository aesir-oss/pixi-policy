# pixi-policy

Write down what your pixi environments are allowed to contain, and check it everywhere pixi runs. One file,
`pixi-policy.toml`, committed beside `pixi.toml` and `pixi.lock`; one command, `pixi policy`, that reports every package,
source, license or manifest setting the policy does not allow, with the reason and a fix hint, and exits non-zero so
CI can stop the merge.

```sh
pixi policy init     # write a policy the workspace passes today
pixi policy          # check it (the same as `pixi policy check`)
pixi policy explain  # every rule; `pixi policy explain <RULE>` for one, with its keys
```

pixi-policy reads three files and nothing else: it needs no server, no database and no network, and every check runs
offline. It is a single binary that pixi runs as `pixi policy`.

## What it checks

| Family | Rules | Checks that |
|---|---|---|
| [Sources](rules.md#sources-channels) | `sources.channels`, `sources.indexes`, `sources.git`, `sources.url`, `sources.path` | conda packages come only from allowed channels, PyPI packages only from allowed indexes, and nothing from git, a direct URL or a local path unless allowed |
| [Bans](rules.md#bans-deny) | `bans.deny` | no banned package, version range or build is in any environment |
| [Licenses](licenses.md) | `licenses.deny`, `licenses.review`, `licenses.not-allowed`, `licenses.unknown` | every package can be used under the licenses the policy allows |
| [Manifest](rules.md#manifest-wildcard-spec) | `manifest.wildcard-spec`, `manifest.python-pinned`, `manifest.required-platforms` | `pixi.toml` gives no `*` specs, pins Python to a minor version and lists the required platforms |
| [Lock](rules.md#lock-present) | `lock.present`, `lock.complete`, `lock.in-sync` | `pixi.lock` exists, locks every environment for every platform, and still satisfies the manifest |
| [Waivers](waivers.md) | `waivers.expired`, `waivers.unused`, `waivers.too-long` | every exception has a reason and an end date, and still matches something |

Every environment and every platform in `pixi.lock` is checked. The [rule catalog](rules.md) says what each rule
checks, and the [policy file reference](reference.md) lists every key with its type, allowed values and default.

## Install

| How | Command |
|---|---|
| From PyPI (the wheel carries only the binary) | `uv tool install pixi-policy`, `pipx install pixi-policy` or `pip install pixi-policy` |
| In a pixi workspace, pinned with the rest of its tools | `[feature.lint.pypi-dependencies] pixi-policy = ">=0.1,<0.2"` in a feature that has Python, then `pixi run -e lint pixi-policy` |
| A release archive | download it from [GitHub Releases](https://github.com/aesir-oss/pixi-policy/releases) and check where it came from with `gh attestation verify <archive> --repo aesir-oss/pixi-policy` |

pixi finds any `pixi-<name>` executable on `PATH`, so once `pixi-policy` is installed `pixi policy` works. A
conda-forge package, for `pixi global install`, is planned
([#6](https://github.com/aesir-oss/pixi-policy/issues/6)).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing failed. Warnings may still be reported |
| 1 | At least one finding is an error |
| 2 | The policy, the manifest or the lockfile could not be read |

## Next

- [Getting started](getting-started.md): from `pixi policy init` to a policy that fails the build
- [In development and CI](ci.md): a pixi task, a pre-commit hook and a GitHub Actions step
- [Output formats](output.md): text, JSON and SARIF
