<!-- Generated from the code by `pixi run policy-docs`; edit crates/pixi-policy/src/keys.rs or src/explain.rs instead. -->

# Policy file reference

Every key `pixi-policy.toml` accepts. A key the table does not list is an error, so a misspelt key cannot quietly check nothing. `pixi policy explain <RULE>` prints the rows for one rule's keys. The When extended column says how a key combines when one policy extends another; see [Sharing a policy](extends.md).

## Top-level keys {#top-level}

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `max-waiver-days` | integer | 0 or more: the furthest a waiver's expires may be from today, in days; 0 turns the check off | 365 | no | may only be stricter, unless overridable | [`waivers.too-long`](rules.md#waivers-too-long) |

## `[policy]` {#policy}

A table. When it is left out: the policy extends nothing, and nothing may loosen it.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[policy] extends` | list of strings | paths of the policies this one builds on, relative to this file. They apply in order, then this file on top: it may tighten anything, and loosen only what they list in overridable | []: the policy stands alone | no | this file only | – |
| `[policy] overridable` | list of strings | IDs of keys a policy extending this one may loosen: the keys that may only narrow or be stricter ("licenses.allow", "sources.allow-git", "max-waiver-days") | []: nothing this policy sets may be loosened | no | this file only | – |

## `[sources]` {#sources}

A table. When it is left out: no source rule runs.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[sources] allowed-channels` | list of strings | channel names or URLs. A name ("conda-forge") matches its anaconda.org and prefix.dev URLs; any other host is given by URL ("https://conda.example.com/prod"). Trailing slashes and host case do not matter | not set: conda packages may come from any channel | no | may only narrow, unless overridable | [`sources.channels`](rules.md#sources-channels) |
| `[sources] allowed-indexes` | list of strings | PyPI index URLs ("https://pypi.org/simple"). Trailing slashes and host case do not matter | not set: PyPI packages may come from any index | no | may only narrow, unless overridable | [`sources.indexes`](rules.md#sources-indexes) |
| `[sources] allow-git` | boolean | true, false | true: packages may come from a git repository | no | may only be stricter, unless overridable | [`sources.git`](rules.md#sources-git) |
| `[sources] allow-url` | boolean | true, false | true: packages may come from a direct URL | no | may only be stricter, unless overridable | [`sources.url`](rules.md#sources-url) |
| `[sources] allow-path` | boolean | true, false | true: packages may come from a local path | no | may only be stricter, unless overridable | [`sources.path`](rules.md#sources-path) |

## `[bans]` {#bans}

A table. When it is left out: nothing is banned.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[bans] deny` | list of tables | one table per ban, with the fields below | []: nothing is banned | no | adds up | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: name` | string | a package name. A PyPI name also catches a conda package that provides it | none | yes | – | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: version` | string | a version range: conda's syntax for conda packages, PEP 440 for PyPI ones ("<3", ">=1.0,<1.1.1w") | not set: every version is banned | no | – | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: build` | string | a conda build-string pattern, with \* matching any run of characters ("\*_cuda\*"); conda packages only | not set: every build is banned | no | – | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: kind` | string | "conda", "pypi" | not set: both kinds | no | – | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: reason` | string | any text; printed with the finding | none | no | – | [`bans.deny`](rules.md#bans-deny) |
| `[bans] deny: use-instead` | string | any text; printed as the finding's fix hint | none | no | – | [`bans.deny`](rules.md#bans-deny) |

## `[licenses]` {#licenses}

A table. When it is left out: no license rule runs.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[licenses] allow` | list of strings | SPDX license identifiers, or patterns with \* expanded against the SPDX license list ("LGPL-\*"). An -or-later entry accepts later versions of the same license | []: any license that is not denied is acceptable | no | may only narrow, unless overridable | [`licenses.not-allowed`](rules.md#licenses-not-allowed) |
| `[licenses] review` | list of strings | SPDX license identifiers or patterns, as for allow | [] | no | adds up | [`licenses.review`](rules.md#licenses-review), [`licenses.not-allowed`](rules.md#licenses-not-allowed) |
| `[licenses] deny` | list of strings | SPDX license identifiers or patterns, as for allow | [] | no | adds up | [`licenses.deny`](rules.md#licenses-deny) |
| `[licenses] unknown` | string | "warn", "error", "allow" | "warn" | no | may only be stricter, unless overridable | [`licenses.unknown`](rules.md#licenses-unknown) |

## `[manifest]` {#manifest}

A table. When it is left out: no manifest rule runs.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[manifest] wildcard-spec` | boolean | true, false | true once the table exists; without the table the rule is off | no | may only be stricter, unless overridable | [`manifest.wildcard-spec`](rules.md#manifest-wildcard-spec) |
| `[manifest] python-pinned` | boolean | true, false | true once the table exists; without the table the rule is off | no | may only be stricter, unless overridable | [`manifest.python-pinned`](rules.md#manifest-python-pinned) |
| `[manifest] required-platforms` | list of strings | pixi platform names ("linux-64", "linux-aarch64", "osx-64", "osx-arm64", "win-64", …) | not set: no platform is required | no | adds up | [`manifest.required-platforms`](rules.md#manifest-required-platforms) |

## `[lock]` {#lock}

A table. When it is left out: no lock rule runs, and a missing pixi.lock is an input error (exit 2).

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[lock] present` | boolean | true, false | true once the table exists; without the table the rule is off | no | may only be stricter, unless overridable | [`lock.present`](rules.md#lock-present) |
| `[lock] complete` | boolean | true, false | true once the table exists; without the table the rule is off | no | may only be stricter, unless overridable | [`lock.complete`](rules.md#lock-complete) |
| `[lock] in-sync` | boolean | true, false | true once the table exists; without the table the rule is off | no | may only be stricter, unless overridable | [`lock.in-sync`](rules.md#lock-in-sync) |

## `[[waivers]]` {#waivers}

A list of tables. When it is left out: no exceptions.

| Key | Type | Allowed values | Default | Required | When extended | Rules |
|---|---|---|---|---|---|---|
| `[[waivers]] rule` | string | the ID of a policy rule, as `pixi policy explain` lists it ("licenses.deny"); waivers.\* findings cannot be waived | none | yes | – | [`waivers.unused`](rules.md#waivers-unused) |
| `[[waivers]] package` | string | the package's name, as the finding names it (case does not matter). Findings that name no package, such as the lock rules', cannot be waived | none | yes | – | [`waivers.unused`](rules.md#waivers-unused) |
| `[[waivers]] version` | string | an exact version, as the finding names it | not set: every version | no | – | [`waivers.unused`](rules.md#waivers-unused) |
| `[[waivers]] environment` | string | an environment name from pixi.toml | not set: every environment | no | – | [`waivers.unused`](rules.md#waivers-unused) |
| `[[waivers]] platform` | string | a pixi platform name ("linux-64") | not set: every platform | no | – | [`waivers.unused`](rules.md#waivers-unused) |
| `[[waivers]] reason` | string | any text: why the exception is acceptable, and until when | none | yes | – | – |
| `[[waivers]] expires` | date | a TOML date, YYYY-MM-DD, unquoted: the last day the waiver applies | none | yes | – | [`waivers.expired`](rules.md#waivers-expired), [`waivers.too-long`](rules.md#waivers-too-long) |
