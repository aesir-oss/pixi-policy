# Known vulnerabilities

`[advisories]` fails a workspace that locks a package with a known vulnerability, without running a second tool:

```toml
[advisories]
fail-on = "high"            # an advisory at or above high fails (the default)
known-exploited = "error"   # one in CISA's Known Exploited Vulnerabilities catalog fails, whatever its severity
epss = 0.1                  # one FIRST rates 10% or more likely to be exploited in 30 days fails (off by default)
```

`[advisories]` on its own fails on high and critical advisories and on known exploited ones. Each finding names the
advisory and its CVE, and the help names the version that fixes it:

```text
error[advisories.vulnerable] urllib3 1.26.4: GHSA-v845-jxx5-vc9f (CVE-2023-43804), high severity: `Cookie` HTTP header isn't stripped on cross-origin redirects
  --> pixi.lock: environment "default", linux-64
  = help: upgrade to 1.26.17 or later; see https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f
```

Without the table, no advisory is looked up and nothing is fetched. The keys are in the
[reference](reference.md#advisories), the rules in the [rule catalog](rules.md#advisories-vulnerable).

## Where the data comes from

The sources are the ones `pixi sbom --vulns` reads, read the same way, so both tools report the same advisories:

- [OSV](https://osv.dev) for the advisories (GitHub's, the PyPI advisory database's and the rest), with their
  severity from the database's rating or the CVSS v3 vector, whichever is worse. Records about the same vulnerability,
  such as a GHSA and a PYSEC entry sharing a CVE, are one advisory.
- [CISA's KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for `known-exploited`. With
  `known-exploited = "error"` (the default), a known exploited advisory counts as critical, so it fails whatever
  `fail-on` is, and the message keeps its own rating: `critical severity (rated medium), known exploited`. With
  `"warn"` or `"allow"` its rating is left alone. An EPSS score does not change a rating.
- [FIRST's EPSS scores](https://www.first.org/epss/) for `epss`, asked for only when `epss` is set. An advisory with
  several CVEs takes the highest score.

OSV has no conda ecosystem, so a conda package is looked up by its PyPI identity: the PyPI purls pixi.lock states for
it, and, for a conda-forge package the lockfile states none for, the name conda-forge's conda-to-PyPI mapping gives it
(the mapping pixi uses). `pypi-mapping = "lock"` uses the lockfile's purls only, as `pixi sbom --vulns` does by default;
`pixi sbom --vulns --pypi-mapping prefix` matches the default here. A conda package with no PyPI identity, such as
openssl, is not covered, and neither is a PyPI package built from a git checkout or a local path.

## Caching, offline use and mirrors

Answers are cached beside the [extended policies](extends.md#extending-a-url): OSV's for an hour, its records until
they change, the catalog, the scores and the mapping for a day. When a download fails, a stale copy stands in.

When the data cannot be read at all, because the network is down and nothing is cached or `PIXI_POLICY_OFFLINE` is
set with an empty cache, `advisories.unavailable` fails the check: a gate that passes when it could see nothing would be
worse than one that stops. To run offline in CI, run once online and keep `PIXI_POLICY_CACHE_DIR` in the CI cache.

On a network that blocks the public services, point these at mirrors that answer the same way:

| Variable | Default |
|---|---|
| `PIXI_POLICY_OSV_URL` | `https://api.osv.dev` |
| `PIXI_POLICY_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| `PIXI_POLICY_EPSS_URL` | `https://api.first.org/data/v1/epss` |
| `PIXI_POLICY_MAPPING_URL` | `https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json` |

## Accepting an advisory

A waiver with `advisory` accepts one advisory on one package, by its id or any alias:

```toml
[[waivers]]
rule = "advisories.vulnerable"
package = "urllib3"
advisory = "CVE-2023-43804"
reason = "no redirects to other origins; SEC-123"
expires = 2027-03-31
```

Without `advisory`, the waiver accepts every advisory on the package, including ones published after it was written.

## VEX statements

A VEX document says why an advisory does not affect a product. `[advisories] vex` names the ones the check reads:

```toml
[advisories]
vex = ["security/vex.cdx.json", "https://github.com/acme/policies/raw/v3/vendor.openvex.json"]
```

Each entry is a path relative to the policy file that names it, or a pinned https URL (a tag or a commit in it),
fetched once and cached like an [extended policy](extends.md). A shared policy can carry its VEX: an entry in a base
is found beside that base, by its path or relative to its URL, and every file's entries add up.

pixi-policy reads CycloneDX JSON (a VEX, or an SBOM with `vulnerabilities[].analysis`) and OpenVEX, as pixi-sbom's
`--vex-in` does. A statement applies to an advisory finding when it names the advisory by its id or any alias, and
names the package by a purl (`pkg:pypi/urllib3@1.26.4`; without a version, every version), or names no product at
all. A conda package is matched by its own purl and by the PyPI purls it was looked up by. When several statements
apply, the last one wins.

| State | OpenVEX status | The finding |
|---|---|---|
| `not_affected`, `false_positive` | `not_affected` | is waived, with the statement |
| `resolved`, `resolved_with_pedigree` | `fixed` | is waived, with the statement |
| `exploitable`, `in_triage` | `affected`, `under_investigation` | still fails |

A waived finding is listed with the others, its statement in place of a waiver:

```text
waived[advisories.vulnerable] urllib3 1.26.4: GHSA-v845-jxx5-vc9f (CVE-2023-43804), high severity: ... (pixi.lock: environment "default", linux-64); VEX: not_affected (code_not_reachable), vex.cdx.json: never parses cookies
```

In JSON the entry has `vex` (`state`, `justification`, `detail`, `source`) instead of `waiver`; in SARIF it is a
suppressed result with the statement as its justification. A statement does not expire; a VEX file that cannot be
read or is neither format stops the check with exit code 2.
