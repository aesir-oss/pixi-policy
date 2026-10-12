# Waivers

A waiver is an exception for one rule and one package, with a reason and an end date. The waived finding is still
reported, as waived, and does not fail the check. The day after `expires`, it fails again.

```toml
[[waivers]]
rule = "licenses.deny"
package = "readline"
reason = "dev only; LEGAL-1234"
expires = 2027-03-31
```

## What a waiver matches

A waiver covers a finding when its `rule` and `package` match the finding's (the package name ignoring case), and
each of `version`, `environment` and `platform` that it gives matches too. Leave those out to cover every version,
environment and platform:

```toml
[[waivers]]
rule = "bans.deny"
package = "openssl"
version = "1.1.1w"
environment = "legacy"
platform = "linux-64"
reason = "the legacy environment ships to RHEL 7 until it is retired"
expires = 2026-12-31
```

Only findings about a package can be waived. The lock rules name no package; turn one off with its key
(`[lock] in-sync = false`) instead. The findings about waivers themselves (`waivers.*`) cannot be waived.

## Every waiver ends

`expires` is required, as a TOML date, `YYYY-MM-DD`, unquoted. The policy reports three things about waivers, all as
warnings at the waiver's line in the policy:

| Rule | When | What to do |
|---|---|---|
| [`waivers.expired`](rules.md#waivers-expired) | `expires` has passed; what it waived fails again | fix the finding, or renew the waiver with a new date and a reason that still holds |
| [`waivers.unused`](rules.md#waivers-unused) | it matches no finding | remove it, or correct its rule, package, version, environment or platform |
| [`waivers.too-long`](rules.md#waivers-too-long) | `expires` is more than `max-waiver-days` away (365 by default) | bring `expires` closer, or raise `max-waiver-days` |

`max-waiver-days` sets how far out a waiver may run; it is a top-level key, so it goes above the first table. `0`
turns the check off:

```toml
max-waiver-days = 180

[licenses]
deny = ["GPL-3.0-*"]
```

## Moving from pixi-sbom's `--ignore-license`

pixi-sbom's `--ignore-license PACKAGE:WHY` has no end date. Write each one as a waiver of `licenses.deny` (or
`licenses.not-allowed`) for that package, with the reason and a date to look at it again.
