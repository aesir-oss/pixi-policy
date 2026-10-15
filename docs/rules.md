<!-- Generated from the code by `pixi run policy-docs`; edit crates/pixi-policy/src/keys.rs or src/explain.rs instead. -->

# Rules

Every rule `pixi policy check` runs, with the text `pixi policy explain <RULE>` prints. Each rule's keys are in the [policy file reference](reference.md).

| Rule | Checks |
|---|---|
| [`sources.channels`](#sources-channels) | Conda packages come only from the channels the policy allows |
| [`sources.indexes`](#sources-indexes) | PyPI packages come only from the indexes the policy allows |
| [`sources.git`](#sources-git) | No package comes from a git repository unless the policy allows it |
| [`sources.url`](#sources-url) | No package comes from a direct URL unless the policy allows it |
| [`sources.path`](#sources-path) | No package comes from a local path unless the policy allows it |
| [`bans.deny`](#bans-deny) | No package, or package version, the policy bans |
| [`licenses.deny`](#licenses-deny) | No package needs a license the policy denies |
| [`licenses.review`](#licenses-review) | Packages that need a license under review are reported for it |
| [`licenses.not-allowed`](#licenses-not-allowed) | Every package can be used under the licenses the policy allows |
| [`licenses.unknown`](#licenses-unknown) | Every package declares an SPDX license |
| [`advisories.vulnerable`](#advisories-vulnerable) | A package has a known vulnerability at or above fail-on, known exploited, or above the EPSS threshold |
| [`advisories.unknown`](#advisories-unknown) | A package has a known vulnerability whose severity no advisory gives |
| [`advisories.unavailable`](#advisories-unavailable) | The advisory data cannot be read, so no package could be checked |
| [`freshness.build-age`](#freshness-build-age) | A conda package was built longer ago than max-build-age-days |
| [`freshness.majors-behind`](#freshness-majors-behind) | A conda package is more major versions behind its channel's newest than allowed |
| [`freshness.archived`](#freshness-archived) | A conda-forge package comes from an archived feedstock |
| [`freshness.unknown`](#freshness-unknown) | The channel data says nothing about a conda package a freshness rule checks |
| [`freshness.unavailable`](#freshness-unavailable) | The channel data cannot be read, so no package could be checked for freshness |
| [`python.older`](#python-older) | No environment runs a Python older than the policy's standard |
| [`python.newer`](#python-newer) | No environment runs a Python newer than the policy's standard |
| [`manifest.wildcard-spec`](#manifest-wildcard-spec) | No dependency is given as `\*` |
| [`manifest.python-pinned`](#manifest-python-pinned) | Python is constrained to one minor version or narrower |
| [`manifest.required-platforms`](#manifest-required-platforms) | The workspace lists every platform the policy requires |
| [`lock.present`](#lock-present) | The workspace has a pixi.lock |
| [`lock.complete`](#lock-complete) | Every environment is locked for every platform it is solved for |
| [`lock.in-sync`](#lock-in-sync) | pixi.lock still satisfies the manifest |
| [`waivers.expired`](#waivers-expired) | A waiver has expired, and what it waived fails again |
| [`waivers.unused`](#waivers-unused) | A waiver matches no finding |
| [`waivers.too-long`](#waivers-too-long) | A waiver runs further out than max-waiver-days |

## `sources.channels` {#sources-channels}

Conda packages come only from the channels the policy allows.

Key: [sources] allowed-channels, a list of channel names or URLs. A name ("conda-forge") matches its anaconda.org and prefix.dev URLs only; any other host is listed by URL. Mirrors are matched as the channel they mirror, since pixi.lock records that channel.

```toml
[sources]
allowed-channels = ["conda-forge", "https://conda.example.com/prod"]
```

Keys: [`[sources] allowed-channels`](reference.md#sources).

## `sources.indexes` {#sources-indexes}

PyPI packages come only from the indexes the policy allows.

Key: [sources] allowed-indexes, a list of PyPI index URLs (trailing slashes and host case do not matter). pixi.lock records a wheel's index; one from the default index is checked against it.

```toml
[sources]
allowed-indexes = ["https://pypi.org/simple"]
```

Keys: [`[sources] allowed-indexes`](reference.md#sources).

## `sources.git` {#sources-git}

No package comes from a git repository unless the policy allows it.

Key: [sources] allow-git (default: allowed). Set it to false to fail any package, conda (pixi-build) or PyPI, that comes from a git repository.

```toml
[sources]
allow-git = false
```

Keys: [`[sources] allow-git`](reference.md#sources).

## `sources.url` {#sources-url}

No package comes from a direct URL unless the policy allows it.

Key: [sources] allow-url (default: allowed). Set it to false to fail any package that comes from a direct URL: an archive, not a channel or an index.

```toml
[sources]
allow-url = false
```

Keys: [`[sources] allow-url`](reference.md#sources).

## `sources.path` {#sources-path}

No package comes from a local path unless the policy allows it.

Key: [sources] allow-path (default: allowed). Set it to false to fail any package that comes from a local path, including a workspace package pixi builds from source.

```toml
[sources]
allow-path = false
```

Keys: [`[sources] allow-path`](reference.md#sources).

## `bans.deny` {#bans-deny}

No package, or package version, the policy bans.

Key: [bans] deny, a list of bans: name, and optionally version (conda's rules for conda packages, PEP 440 for PyPI ones), build (a conda build-string pattern), kind ("conda" or "pypi"), reason and use-instead. A ban on a PyPI name also catches a conda package that provides it.

```toml
[bans]
deny = [
  { name = "pycrypto", reason = "unmaintained", use-instead = "pycryptodome" },
  { name = "openssl", version = "<3", reason = "EOL" },
]
```

Keys: [`[bans] deny`](reference.md#bans), [`[bans] deny: name`](reference.md#bans), [`[bans] deny: version`](reference.md#bans), [`[bans] deny: build`](reference.md#bans), [`[bans] deny: kind`](reference.md#bans), [`[bans] deny: reason`](reference.md#bans), [`[bans] deny: use-instead`](reference.md#bans).

## `licenses.deny` {#licenses-deny}

No package needs a license the policy denies.

Key: [licenses] deny, SPDX identifiers or patterns ("GPL-3.0-*"). A package fails when its license cannot be satisfied without a denied license: MIT OR GPL-3.0-only passes, since MIT is an option. The verdict is the one pixi-sbom's --deny-license gives.

```toml
[licenses]
deny = ["GPL-3.0-*", "AGPL-*"]
```

Keys: [`[licenses] deny`](reference.md#licenses).

## `licenses.review` {#licenses-review}

Packages that need a license under review are reported for it.

Key: [licenses] review, SPDX identifiers or patterns. A package that needs one is reported as a warning; review licenses count as allowed for licenses.not-allowed.

```toml
[licenses]
review = ["LGPL-*"]
```

Keys: [`[licenses] review`](reference.md#licenses).

## `licenses.not-allowed` {#licenses-not-allowed}

Every package can be used under the licenses the policy allows.

Key: [licenses] allow. When given, a package fails unless its license can be satisfied with allow and review licenses alone. An -or-later requirement accepts later versions of the same license.

```toml
[licenses]
allow = ["MIT", "BSD-3-Clause", "Apache-2.0"]
```

Keys: [`[licenses] allow`](reference.md#licenses), [`[licenses] review`](reference.md#licenses).

## `licenses.unknown` {#licenses-unknown}

Every package declares an SPDX license.

Key: [licenses] unknown = "warn" (default), "error" or "allow": what a package with no license, or one that is not an SPDX expression, gets. pixi.lock records no PyPI licenses, so every PyPI package is unknown until pixi-policy reads license files.

```toml
[licenses]
unknown = "error"
```

Keys: [`[licenses] unknown`](reference.md#licenses).

## `advisories.vulnerable` {#advisories-vulnerable}

A package has a known vulnerability at or above fail-on, known exploited, or above the EPSS threshold.

Keys: [advisories] fail-on (default "high"), known-exploited (default "error") and epss (not set by default). A package fails for each advisory at or above fail-on, in CISA's Known Exploited Vulnerabilities catalog, or with an EPSS score at or above epss. Advisories are OSV's, as pixi-sbom --vulns reads them; a conda package is looked up by its PyPI identity (pypi-mapping). The help names the version that fixes it. Waive one advisory with a waiver's advisory key.

```toml
[advisories]
fail-on = "high"
known-exploited = "error"
epss = 0.1
```

Keys: [`[advisories] fail-on`](reference.md#advisories), [`[advisories] known-exploited`](reference.md#advisories), [`[advisories] epss`](reference.md#advisories), [`[advisories] pypi-mapping`](reference.md#advisories).

## `advisories.unknown` {#advisories-unknown}

A package has a known vulnerability whose severity no advisory gives.

Key: [advisories] unknown = "warn" (default), "error" or "allow": what an advisory gets when no record of it gives a severity or a CVSS v3 vector, unless known-exploited or epss already fail it.

```toml
[advisories]
unknown = "error"
```

Keys: [`[advisories] unknown`](reference.md#advisories), [`[advisories] pypi-mapping`](reference.md#advisories).

## `advisories.unavailable` {#advisories-unavailable}

The advisory data cannot be read, so no package could be checked.

Key: [advisories]. The advisory data could not be read: OSV, CISA's catalog, FIRST's EPSS API or the conda-forge mapping did not answer and nothing was cached, or PIXI_POLICY_OFFLINE is set and the cache is empty. The check fails rather than pass a workspace it could not look at. PIXI_POLICY_OSV_URL, PIXI_POLICY_KEV_URL, PIXI_POLICY_EPSS_URL and PIXI_POLICY_MAPPING_URL point at mirrors.

```toml
[advisories]
```

Keys: .

## `freshness.build-age` {#freshness-build-age}

A conda package was built longer ago than max-build-age-days.

Key: [freshness] max-build-age-days (not set by default). Fails a conda package built more days ago than the limit, by the build time its record in pixi.lock states: no network. A package with no build time is freshness.unknown.

```toml
[freshness]
max-build-age-days = 730
```

Keys: [`[freshness] max-build-age-days`](reference.md#freshness).

## `freshness.majors-behind` {#freshness-majors-behind}

A conda package is more major versions behind its channel's newest than allowed.

Key: [freshness] max-majors-behind (not set by default). Fails a conda package whose major version (the leading number) is more than the limit behind the newest release in the repodata of the channel and subdir pixi.lock names for it, so a mirror is judged by its own contents. Prereleases do not count as newest. PyPI packages are not checked.

```toml
[freshness]
max-majors-behind = 1
```

Keys: [`[freshness] max-majors-behind`](reference.md#freshness).

## `freshness.archived` {#freshness-archived}

A conda-forge package comes from an archived feedstock.

Key: [freshness] archived (on once [freshness] exists). Fails a conda-forge package when every feedstock that builds it is archived, by the conda-forge bot's feedstock list, which can trail an archival on GitHub by a bot cycle (hours).

```toml
[freshness]
archived = true
```

Keys: [`[freshness] archived`](reference.md#freshness).

## `freshness.unknown` {#freshness-unknown}

The channel data says nothing about a conda package a freshness rule checks.

Key: [freshness] unknown = "warn" (default), "error" or "allow": what a conda package gets when a freshness rule cannot judge it: no build time in pixi.lock, not in its channel's repodata, no major version to compare, or no feedstock known to build it.

```toml
[freshness]
unknown = "error"
```

Keys: [`[freshness] max-build-age-days`](reference.md#freshness), [`[freshness] max-majors-behind`](reference.md#freshness), [`[freshness] archived`](reference.md#freshness), [`[freshness] unknown`](reference.md#freshness).

## `freshness.unavailable` {#freshness-unavailable}

The channel data cannot be read, so no package could be checked for freshness.

Key: [freshness]. The channel's repodata or conda-forge's feedstock lists could not be read: the network is down and nothing is cached, or PIXI_POLICY_OFFLINE is set and the cache is empty. The check fails rather than pass packages it could not look at.

```toml
[freshness]
```

Keys: [`[freshness] max-majors-behind`](reference.md#freshness), [`[freshness] archived`](reference.md#freshness).

## `python.older` {#python-older}

No environment runs a Python older than the policy's standard.

Keys: [python] version, the standard minor version, and older = "error" (default), "warn" or "allow". Reports an environment whose Python, as pixi.lock resolves it for each platform, is an older minor version than the standard. Every patch release of the standard matches it; an environment without Python is not checked.

```toml
[python]
version = "3.14"
older = "error"
```

Keys: [`[python] version`](reference.md#python), [`[python] older`](reference.md#python).

## `python.newer` {#python-newer}

No environment runs a Python newer than the policy's standard.

Keys: [python] version, the standard minor version, and newer = "warn" (default), "error" or "allow". Reports an environment whose Python, as pixi.lock resolves it for each platform, is a newer minor version than the standard. Every patch release of the standard matches it; an environment without Python is not checked.

```toml
[python]
version = "3.14"
newer = "error"
```

Keys: [`[python] version`](reference.md#python), [`[python] newer`](reference.md#python).

## `manifest.wildcard-spec` {#manifest-wildcard-spec}

No dependency is given as `*`.

Key: [manifest] wildcard-spec (on once [manifest] exists). Fails a conda or PyPI dependency given as "*" in any dependency table, at its line in the manifest.

```toml
[manifest]
wildcard-spec = true
```

Keys: [`[manifest] wildcard-spec`](reference.md#manifest).

## `manifest.python-pinned` {#manifest-python-pinned}

Python is constrained to one minor version or narrower.

Key: [manifest] python-pinned (on once [manifest] exists). Fails a python dependency whose spec allows more than one minor version (">=3.10"), or has none; "3.12.*" and ">=3.12,<3.13" pass.

```toml
[manifest]
python-pinned = true
```

Keys: [`[manifest] python-pinned`](reference.md#manifest).

## `manifest.required-platforms` {#manifest-required-platforms}

The workspace lists every platform the policy requires.

Key: [manifest] required-platforms, a list of platforms the workspace must list in [workspace] platforms.

```toml
[manifest]
required-platforms = ["linux-64", "osx-arm64"]
```

Keys: [`[manifest] required-platforms`](reference.md#manifest).

## `lock.present` {#lock-present}

The workspace has a pixi.lock.

Key: [lock] present (on once [lock] exists). Fails a workspace without a pixi.lock; without [lock], a missing lockfile is an input error (exit 2) instead.

```toml
[lock]
present = true
```

Keys: [`[lock] present`](reference.md#lock).

## `lock.complete` {#lock-complete}

Every environment is locked for every platform it is solved for.

Key: [lock] complete (on once [lock] exists). Fails an environment the manifest defines that pixi.lock does not lock, or does not lock for one of its platforms.

```toml
[lock]
complete = true
```

Keys: [`[lock] complete`](reference.md#lock).

## `lock.in-sync` {#lock-in-sync}

pixi.lock still satisfies the manifest.

Key: [lock] in-sync (on once [lock] exists). Asks pixi, offline, whether pixi.lock still satisfies the manifest (pixi list --locked); a warning when pixi cannot be run.

```toml
[lock]
in-sync = true
```

Keys: [`[lock] in-sync`](reference.md#lock).

## `waivers.expired` {#waivers-expired}

A waiver has expired, and what it waived fails again.

A [[waivers]] entry whose expires date has passed. What it waived fails again; renew it with a new date and a reason that still holds, or fix the finding.

```toml
[[waivers]]
rule = "licenses.deny"
package = "readline"
reason = "dev only; LEGAL-1234"
expires = 2027-03-31
```

Keys: [`[[waivers]] expires`](reference.md#waivers).

## `waivers.unused` {#waivers-unused}

A waiver matches no finding.

A [[waivers]] entry that matches no finding: its rule, package, version, environment or platform is wrong, or the finding is gone. Remove it.

```toml
[[waivers]]
rule = "bans.deny"
package = "pycrypto"
reason = "replaced in Q3"
expires = 2027-01-31
```

Keys: [`[[waivers]] rule`](reference.md#waivers), [`[[waivers]] package`](reference.md#waivers), [`[[waivers]] version`](reference.md#waivers), [`[[waivers]] environment`](reference.md#waivers), [`[[waivers]] platform`](reference.md#waivers), [`[[waivers]] advisory`](reference.md#waivers).

## `waivers.too-long` {#waivers-too-long}

A waiver runs further out than max-waiver-days.

A [[waivers]] entry whose expires is more than max-waiver-days (default 365) away. The waiver still applies. Set max-waiver-days at the top of the policy; 0 turns the check off.

```toml
max-waiver-days = 180
```

Keys: [`max-waiver-days`](reference.md#top-level), [`[[waivers]] expires`](reference.md#waivers).
