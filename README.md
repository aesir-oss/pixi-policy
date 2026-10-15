# pixi-policy

[![PyPI](https://img.shields.io/pypi/v/pixi-policy.svg)](https://pypi.org/project/pixi-policy/)
[![Docs](https://img.shields.io/badge/docs-pixi--policy-07835d.svg)](https://aesir-oss.github.io/pixi-policy/)

Write down what your [pixi](https://pixi.sh) environments are allowed to contain, and check it everywhere pixi runs.
One file, `pixi-policy.toml`, committed beside `pixi.toml` and `pixi.lock`; one command, `pixi policy`, that reports
every package, source, license or manifest setting the policy does not allow, with the reason and a fix hint, and
exits non-zero so CI can stop the merge.

```sh
pixi policy init     # write a policy the workspace passes today
pixi policy          # check it (the same as `pixi policy check`)
pixi policy explain  # every rule; `pixi policy explain <RULE>` for one, with its keys and defaults
```

It reads three files and needs no server and no database. The network is used only for a shared policy extended by
URL, known vulnerabilities (`[advisories]`) and freshness (`[freshness]`), all cached, so a check runs offline once
they are cached.

`pixi policy facts` writes what pixi.lock says about every environment as JSON, for organizations that keep their
policy in OPA and Rego ([an example](examples/rego/pixi.rego)).

## What it checks

| Family | Checks that |
|---|---|
| `sources` | conda packages come only from allowed channels, PyPI packages only from allowed indexes, and nothing from git, a direct URL or a local path unless allowed |
| `bans` | no banned package, version range or build is in any environment |
| `licenses` | every package can be used under the licenses the policy allows (SPDX allow, review and deny lists) |
| `advisories` | no package has a known vulnerability at or above the policy's severity, known exploited or likely to be exploited (OSV, CISA KEV, EPSS) |
| `freshness` | no conda package is too old a build, too many major versions behind its channel's newest, or from an archived conda-forge feedstock |
| `hygiene` | no PyPI package is one a conda package in the same environment already provides |
| `python` | every environment runs the policy's standard Python minor version (any patch release of it) |
| `manifest` | `pixi.toml` gives no `*` specs, pins Python to a minor version and lists the required platforms |
| `lock` | `pixi.lock` exists, locks every environment for every platform, and still satisfies the manifest |
| `waivers` | every exception has a reason and an end date, and still matches something |

```toml
# pixi-policy.toml
[sources]
allowed-channels = ["conda-forge"]
allowed-indexes = ["https://pypi.org/simple"]

[bans]
deny = [
  { name = "pycrypto", reason = "unmaintained", use-instead = "pycryptodome" },
  { name = "openssl", version = "<3", reason = "EOL" },
]

[licenses]
deny = ["GPL-3.0-*", "AGPL-*"]

[manifest]
required-platforms = ["linux-64", "osx-arm64", "win-64"]

[lock]

[[waivers]]
rule = "licenses.deny"
package = "readline"
reason = "dev only; LEGAL-1234"
expires = 2027-03-31
```

That policy, checked against one of the repository's example workspaces (an excerpt):

```text
error[licenses.deny] ld_impl_linux-64 2.46.1: license GPL-3.0-only cannot be satisfied without a denied license
  --> pixi.lock: environment "default", linux-64
  = help: replace the package, or take the license off [licenses] deny

error[manifest.wildcard-spec] gh: is given as "*" in [dependencies]
  --> pixi.toml:11
  = help: give it a version range, for example the one `pixi add` writes

waived[licenses.deny] readline 8.3: license GPL-3.0-only cannot be satisfied without a denied license (pixi.lock: environment "default", linux-64); waiver: dev only; LEGAL-1234, expires 2027-03-31

4 errors, 0 warnings, 2 waived in 45 packages across 2 environment-platform pairs
```

## Install

```sh
uv tool install pixi-policy     # or: pipx install pixi-policy, pip install pixi-policy
```

The wheel carries only the `pixi-policy` binary, for Linux (x86-64 and aarch64, glibc and musl), macOS and Windows.
pixi runs any `pixi-<name>` executable on `PATH` as `pixi <name>`. Release archives with build provenance are on
[GitHub Releases](https://github.com/aesir-oss/pixi-policy/releases).

## In CI

The exit code is the verdict: 0 nothing failed, 1 a finding is an error, 2 an input could not be read. `--format json`
writes a report with a published schema, and `--format sarif` one for GitHub code scanning:

```yaml
- run: pixi run policy --format sarif --output policy.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: policy.sarif
```

## Documentation

**https://aesir-oss.github.io/pixi-policy/**:
[getting started](https://aesir-oss.github.io/pixi-policy/latest/getting-started/),
[development and CI](https://aesir-oss.github.io/pixi-policy/latest/ci/),
[every rule](https://aesir-oss.github.io/pixi-policy/latest/rules/),
[every key, with its values and default](https://aesir-oss.github.io/pixi-policy/latest/reference/),
[waivers](https://aesir-oss.github.io/pixi-policy/latest/waivers/) and
[output formats](https://aesir-oss.github.io/pixi-policy/latest/output/).

From [Aesir Open Source Solutions](https://github.com/aesir-oss), beside
[pixi-sbom](https://github.com/aesir-oss/pixi-sbom). Apache-2.0. A community project, not affiliated with prefix.dev.
