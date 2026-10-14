# Freshness

`[freshness]` fails a workspace that locks conda packages that are years old, far behind their newest release, or no
longer maintained:

```toml
[freshness]
max-build-age-days = 730   # a build older than two years fails
max-majors-behind = 1      # a package two or more major versions behind its channel's newest fails
archived = true            # a conda-forge package whose feedstock is archived fails (on once the table exists)
```

```text
error[freshness.majors-behind] setuptools 59.8.0: 25 major versions behind 84.0.0, the newest in conda-forge, more than max-majors-behind (1)
  --> pixi.lock: environment "default", linux-64
  = help: upgrade it, or waive it while the upgrade is planned
```

The keys are in the [reference](reference.md#freshness), the rules in the
[rule catalog](rules.md#freshness-build-age). Only conda packages are checked; PyPI packages are not.

## Build age

`max-build-age-days` reads the build time each conda package's record in pixi.lock states, so it needs no network. A
package whose record has no build time is reported as `freshness.unknown`.

## Major versions behind

`max-majors-behind` compares a package's major version, its leading number, with the newest release in the repodata of
the channel pixi.lock installs it from: conda.anaconda.org, prefix.dev or a mirror, whichever the lockfile names. A
mirror is therefore judged by its own contents, and a mirror that lags upstream does not fail a workspace for releases
it cannot install yet.

- The package's own subdir and noarch both count, since packages move between them: setuptools' linux-64 builds stop
  at 65, and its newer releases are noarch.
- Prereleases do not count as the newest release.
- A calendar-versioned package (`2024.8.30`) is compared by its year.
- A package its channel's repodata does not list, or whose major version cannot be read, is `freshness.unknown`.

Repodata is read sharded where the channel serves it (CEP-16, as pixi does): a small index, then one shard per package.
A channel that serves no shards is read whole, from `repodata.json.zst` or `repodata.json`, which for a large channel is
a download of tens of megabytes the first time each day. No repodata is fetched unless `max-majors-behind` is set.

## Archived feedstocks

`archived` asks whether conda-forge has archived the feedstock that builds a conda-forge package: archived feedstocks
get no new builds, so no fixes either. It reads two files the conda-forge bot publishes:

- [`all_feedstocks.json`](https://github.com/regro/cf-graph-countyfair/blob/master/all_feedstocks.json) from
  `regro/cf-graph-countyfair`, listing active and archived feedstocks;
- [`feedstock-outputs.json`](https://github.com/conda-forge/feedstock-outputs/tree/single-file) from
  `conda-forge/feedstock-outputs`, naming the feedstocks that build each package.

!!! note "The list can trail GitHub"
    The archived list is the bot's, regenerated from the conda-forge GitHub organization on each bot cycle, so a
    feedstock archived on GitHub shows up a few hours later, and a cached copy adds up to a day more. A feedstock
    unarchived on GitHub likewise keeps failing until the list and the cache catch up.

A package more than one feedstock builds counts as archived only when all of them are, since the lockfile does not say
which one built it (`libzlib` comes from `zlib` or `zlib-ng`). A package no feedstock is known to build is
`freshness.unknown`. Packages from other channels are not checked.

## Caching, offline use and mirrors

Answers are cached beside the [extended policies](extends.md#extending-a-url): the shard index, a channel's whole
repodata reduced to the newest version of each package, and the feedstock lists for a day, shards for good (they are
named by their content's hash). When a download fails, a stale copy stands in.

When the data cannot be read at all, because the network is down and nothing is cached or `PIXI_POLICY_OFFLINE` is
set with an empty cache, `freshness.unavailable` fails the check; build ages are still judged, since they need no
data. To run offline in CI, run once online and keep `PIXI_POLICY_CACHE_DIR` in the CI cache.

Repodata always comes from each package's own channel. The feedstock lists can come from mirrors:

| Variable | Default |
|---|---|
| `PIXI_POLICY_FEEDSTOCKS_URL` | `https://raw.githubusercontent.com/regro/cf-graph-countyfair/master/all_feedstocks.json` |
| `PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL` | `https://raw.githubusercontent.com/conda-forge/feedstock-outputs/single-file/feedstock-outputs.json` |

A [waiver](waivers.md) accepts a finding for one package, as for every rule.
