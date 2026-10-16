# Getting started

Start from a policy the workspace already passes, commit it, and tighten it one change at a time. Each change is then
a reviewed pull request that says exactly what is no longer allowed.

## 1. Write a starting policy

```sh
pixi policy init
```

`init` writes `pixi-policy.toml` beside `pixi.toml` from what the workspace uses today: the channels and indexes its
packages come from, every license in `pixi.lock`, and its platforms. It never overwrites an existing file; pass
`--policy <file>` to write somewhere else.

```toml
# pixi-policy.toml, written by `pixi policy init` from what this workspace uses today.
[sources]
allowed-channels = ["conda-forge"]
allowed-indexes = ["https://pypi.org/simple"]
allow-git = false
allow-url = false
allow-path = false

[bans]
deny = []  # e.g. { name = "pycrypto", reason = "unmaintained", use-instead = "pycryptodome" }

[licenses]
# Every license the conda packages declare today (shortened here). pixi.lock records no PyPI licenses.
allow = ["Apache-2.0", "BSD-3-Clause", "MIT", "PSF-2.0"]
unknown = "warn"

[manifest]
required-platforms = ["linux-64", "osx-arm64", "win-64"]

[lock]  # present, complete and in-sync are all on
```

## 2. Check it

```sh
pixi policy
```

```text
warning[licenses.unknown] python-dateutil 2.9.0.post0: license "Dual License" in its METADATA is not an SPDX expression (unknown term: 'Dual')
  --> pixi.lock: environment "docs", linux-64
  = help: find the license the package ships and waive this with it as the reason, or set [licenses] unknown = "allow" to stop these

0 errors, 10 warnings, 0 waived in 645 packages across 10 environment-platform pairs
```

Each finding names its rule, the package, where it was found and how to fix it. Errors fail the check (exit code 1);
warnings are reported and do not. Commit `pixi-policy.toml` once the check passes.

## 3. Tighten it

Add what the workspace must never contain, one rule at a time:

```toml
[bans]
deny = [
  { name = "pycrypto", reason = "unmaintained", use-instead = "pycryptodome" },
  { name = "openssl", version = "<3", reason = "EOL" },
]

[licenses]
deny = ["GPL-3.0-*", "AGPL-*"]
```

`pixi policy explain <RULE>` says what a rule checks, gives an example and lists each of its keys with the values
it takes and its default:

```sh
pixi policy explain bans.deny
```

## 4. Waive what has to stay, with an end date

When a finding cannot be fixed yet, waive that one finding with a reason and an `expires` date. It is reported as
waived until then and fails again the day after.

```toml
[[waivers]]
rule = "licenses.deny"
package = "readline"
reason = "dev only; LEGAL-1234"
expires = 2027-03-31
```

See [Waivers](waivers.md) for how a waiver matches a finding.

## 5. Run it in CI

Run the same check on every pull request, so a change to `pixi.toml` or `pixi.lock` that breaks the policy fails
before it merges. [In development and CI](ci.md) has the setup.
