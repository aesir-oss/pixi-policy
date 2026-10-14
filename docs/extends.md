# Sharing a policy

A platform team writes the policy once and every workspace builds on it, instead of copying a file that then drifts.
A policy names the policies it builds on in `[policy] extends`:

```toml
# app/pixi-policy.toml
[policy]
extends = ["../policies/base.toml"]

[bans]
deny = [{ name = "pycrypto", use-instead = "pycryptodome" }]
```

Paths are relative to the file that names them. The bases apply in the order listed, each on top of the ones before,
and the extending file last. A base may extend others in turn; a policy that ends up extending itself is an error, and
a base reached twice is read once. Extending a URL is planned
([#1](https://github.com/aesir-oss/pixi-policy/issues/1)); until then, commit the shared policy, for example as a git
submodule, and extend it by its path.

## Tighten anything, loosen only what the base allows

An extending policy may make anything stricter. It may loosen a value only when the base that set it lists the key in
`[policy] overridable`:

```toml
# policies/base.toml
[policy]
overridable = ["licenses.allow"]

[licenses]
allow = ["MIT", "BSD-3-Clause", "Apache-2.0"]
deny = ["AGPL-*"]
```

Here a workspace may add a license to `allow`, but it cannot remove `AGPL-*` from `deny` or widen anything else the
base sets. Loosening a key the base does not list stops the check with an error (exit 2) that names the key and the
base. For a single package, a [waiver](waivers.md) is the way to loosen: it names the package, the reason and an
expiry, and needs nothing from the base.

How each key combines is the **When extended** column of the [policy reference](reference.md):

| When extended | Keys | What the extending file can do |
|---|---|---|
| adds up | `[bans] deny`, `[licenses] deny` and `review`, `[manifest] required-platforms` | add entries; every file's entries apply and none can be removed |
| may only narrow | `[sources] allowed-channels` and `allowed-indexes`, `[licenses] allow` | replace the list with one that allows no more than the base's |
| may only be stricter | `[sources] allow-git`, `allow-url`, `allow-path`, `[licenses] unknown`, the `[manifest]` and `[lock]` switches, `max-waiver-days` | set a stricter value |
| this file only | `[policy]`, `[[waivers]]` | they are never inherited |

Some details:

- A table turns its rules on for every file after it. When the base has a `[lock]` table, a workspace that sets
  `[lock] in-sync = false` is loosening, even though the base never wrote `in-sync`.
- With an allow list, an entry in `[licenses] review` is also acceptable, so adding a review entry the base's `allow`
  does not cover counts as loosening `licenses.allow`.
- In a chain, a value is checked against every file that set it. A middle policy that lists a key in `overridable`
  lets the files after it loosen only its own value, never past a stricter value set further down that does not list
  the key.
- Waivers stay with the file that holds them, and `max-waiver-days` from a base limits the extending file's waivers.

## What a policy resolves to

`pixi policy show --resolved` prints the merged policy, each value followed by the file it comes from, and marks each
value a policy loosened under its base's `overridable`:

```console
$ pixi policy show --resolved
# pixi-policy.toml, resolved: every policy it extends merged in, each value followed by the file it comes from.
# Read in order: ../policies/base.toml, pixi-policy.toml

[licenses]
allow = ["MIT", "BSD-3-Clause", "Apache-2.0", "PSF-2.0"]  # pixi-policy.toml, loosens ../policies/base.toml (overridable there)
deny = [
  "AGPL-*",  # ../policies/base.toml
]
```

`pixi policy show` without `--resolved` prints the policy file as written.
