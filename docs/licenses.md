# License policy with pixi-policy

pixi-policy's `[licenses]` table is the policy-file form of pixi-sbom's license gate (`--allow-license`,
`--deny-license`, `--require-license`). Both tools evaluate a license expression with the same verdict; pixi-policy also reads
common non-SPDX spellings (see [How a license string is read](#how-a-license-string-is-read)).

```toml
# pixi-policy.toml
[licenses]
allow = ["MIT", "BSD-3-Clause", "Apache-2.0", "PSF-2.0"]
review = ["LGPL-*"]
deny = ["GPL-3.0-*", "AGPL-*"]
unknown = "warn"     # or "error", "allow"
ambiguous = "warn"   # or "error", "allow"
```

| Rule | Severity | Finds a package whose license… |
|---|---|---|
| `licenses.deny` | error | cannot be satisfied without a `deny` license (`MIT OR GPL-3.0-only` passes: MIT is an option) |
| `licenses.not-allowed` | error | cannot be satisfied with `allow` and `review` licenses alone (only when `allow` is given) |
| `licenses.review` | warning | needs a `review` license |
| `licenses.unknown` | `unknown` | is missing, or is not an SPDX expression |
| `licenses.ambiguous` | `ambiguous` | is a name that could be more than one SPDX license (`BSD`, `GPL`, `LGPL2`, `Apache`) |

Entries are SPDX identifiers, or patterns with `*` that are expanded against the SPDX license list (`LGPL-*` is every
LGPL identifier). An `-or-later` entry accepts later versions of the same license, as in pixi-sbom.

## How a license string is read

A license that is an SPDX expression is used as it is. Common spellings that name one license are read as it from a
reviewed table: `BSD 3-Clause`, `New BSD License` and `3-clause BSD License` are `BSD-3-Clause`; `Apache License 2.0`
and `ASL 2.0` are `Apache-2.0`; `PSF` and `Python Software Foundation License` are `PSF-2.0`; `GPL-3` is
`GPL-3.0-only`; `LGPLv3+` is `LGPL-3.0-or-later`; `Expat` and `MIT/X11` are `MIT`. A finding about such a package shows
both, `license PSF-2.0 (pixi.lock says "PSF") needs a review`, so a reading can be checked.

A name that does not say which license it is (`BSD`, `GPL`, `LGPL`, `LGPL2`, `BSD Like`, a bare `Apache`) is never
guessed at: it is `licenses.ambiguous`. Find the license the package ships and [waive](waivers.md) the finding with it
as the reason, or ask the package's maintainers to state an SPDX license.

pixi-sbom's gate does not read this table yet, so a package spelt this way can pass one and be reported by the other.

## Moving from pixi-sbom's flags

| pixi-sbom | pixi-policy |
|---|---|
| `--allow-license MIT --allow-license Apache-2.0` | `[licenses] allow = ["MIT", "Apache-2.0"]` |
| `--deny-license GPL-3.0-only` | `[licenses] deny = ["GPL-3.0-only"]` |
| `--require-license` | `[licenses] unknown = "error"` |
| no `--require-license` | `[licenses] unknown = "allow"` (the default, `"warn"`, reports them without failing) |
| `--ignore-license PACKAGE:WHY` | a [waiver](waivers.md) with a reason and an expiry date |
| (no equivalent) | `[licenses] review = [...]`, reported as warnings |
| exit code 3 on a violation | exit code 1 on an error finding |

## What pixi-policy reads

Licenses come from `pixi.lock` only, offline. It records them for conda packages and never for PyPI ones, so every PyPI
package is `licenses.unknown` until pixi-policy 0.2.0 reads license files; set `unknown = "allow"` to stop those
warnings meanwhile. pixi-sbom's gate also covers npm packages it reads from a `package-lock.json` (and licenses it
fetches with `--fetch-licenses`); pixi-policy checks the packages in `pixi.lock`.
