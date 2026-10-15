# Facts for OPA and Rego

An organization that already writes its policy in [Rego](https://www.openpolicyagent.org/docs/policy-language) can
give OPA what pixi-policy knows about a workspace, rather than learn a second policy language:

```console
pixi policy facts --output facts.json
opa eval --input facts.json --data policy.rego "data.pixi.policy.deny"
```

`pixi policy facts` reads `pixi.lock` only, offline, and writes every environment and platform it locks with their
packages. The shape is [pixi-policy-facts.schema.json](schemas/pixi-policy-facts.schema.json), versioned like the
[JSON report](output.md#json): fields may be added, and a renamed or removed field raises `version`.

```json
{
  "version": 1,
  "tool": { "name": "pixi-policy", "version": "0.3.0" },
  "workspace": { "manifest": "pixi.toml", "lockfile": "pixi.lock" },
  "environments": [
    {
      "name": "default",
      "platform": "linux-64",
      "packages": [
        {
          "name": "readline",
          "version": "8.3",
          "kind": "conda",
          "purl": "pkg:conda/readline@8.3?build=hd6e31c0_1&channel=conda-forge&subdir=linux-64&type=conda",
          "provides_pypi": [],
          "origin": { "type": "channel", "url": "https://conda.anaconda.org/conda-forge/", "channel": "conda-forge" },
          "license": { "declared": "GPL-3.0-only", "spdx": "GPL-3.0-only", "status": "spdx" },
          "build": "hd6e31c0_1",
          "build_number": 1,
          "timestamp": 1787033801,
          "subdir": "linux-64",
          "sha256": "01b3fe073a66e321970d09e04b388708f8cbdca5cdfbfcb7c9eeb470ad10383d",
          "requires_python": null
        }
      ]
    }
  ]
}
```

| Field | What it holds |
|---|---|
| `kind` | `conda` (an archive from a channel or URL), `conda-source` (built from source by pixi-build) or `pypi` |
| `origin.type` | `channel`, `index`, `git`, `url` or `path`: where the package comes from, as the `sources.*` rules see it |
| `provides_pypi` | the PyPI distributions pixi.lock states a conda package provides (conda `msgpack-python` provides `msgpack`) |
| `license.spdx` | the SPDX expression pixi-policy reads the declared license as, through its [table of spellings](licenses.md#how-a-license-string-is-read) |
| `license.status` | `spdx`, `text` (not an SPDX expression), `ambiguous` or `missing` (pixi.lock records no PyPI licenses) |

## An example

[examples/rego/pixi.rego](https://github.com/aesir-oss/pixi-policy/blob/main/examples/rego/pixi.rego) writes three of
the built-in rules in Rego:

```rego
package pixi.policy

settings := {
	"allowed_channels": {"conda-forge"},
	"banned": {"py"},
	"denied_licenses": {"GPL-3.0-only"},
}

packages contains [env.name, env.platform, pkg] if {
	some env in input.environments
	some pkg in env.packages
}

deny contains {"rule": "sources.channels", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.origin.type == "channel"
	not pkg.origin.channel in settings.allowed_channels
}

deny contains {"rule": "bans.deny", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.name in settings.banned
}

deny contains {"rule": "licenses.deny", "package": pkg.name, "environment": env, "platform": platform} if {
	some [env, platform, pkg] in packages
	pkg.license.spdx in settings.denied_licenses
}
```

It finds what this pixi-policy.toml finds, except that its license rule compares single identifiers where
pixi-policy evaluates whole SPDX expressions:

```toml
[sources]
allowed-channels = ["conda-forge"]

[bans]
deny = [{ name = "py" }]

[licenses]
deny = ["GPL-3.0-only"]
```

CI runs the example's tests with `opa test` against the facts of an example workspace, and checks they expect what
pixi-policy's own rules find there: `pixi run -e rego rego-test` locally.
