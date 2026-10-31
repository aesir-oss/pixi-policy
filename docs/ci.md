# In development and CI

The policy lives in the repository, so a laptop, a pre-commit hook and CI all check exactly the same rules. pixi-policy
needs nothing running beside it: it reads `pixi.toml`, `pixi.lock` and the policy, and exits.

## What a run needs

- **`pixi.lock`, committed.** Every rule except the manifest ones reads it. Without a `[lock]` table, a missing lockfile
  is an input error (exit 2); with one, it is a `lock.present` finding.
- **pixi on `PATH`.** `lock.in-sync` asks pixi, offline, whether the lockfile still satisfies the manifest
  (`pixi list --locked`). When pixi cannot be run, that check is a warning instead.
- **`pixi-policy.toml`**, beside `pixi.toml` or named with `--policy`. A run without a policy is an error, never a pass.

## A pixi task

Pin pixi-policy with the workspace's other tools, in a feature that has Python, and give it a task:

```toml
# pixi.toml
[feature.lint.dependencies]
python = "3.12.*"

[feature.lint.pypi-dependencies]
pixi-policy = ">=0.1,<0.2"

[feature.lint.tasks]
policy = "pixi-policy"

[environments]
lint = { features = ["lint"], solve-group = "default" }
```

`pixi run policy` then runs the same version for everyone. Extra arguments pass through:
`pixi run policy --format json`.

## Checking before you install

`pixi lock` cannot run anything after it solves, so `pixi policy lock` does the three steps in one:

```console
pixi policy lock             # pixi lock, then check the new pixi.lock
pixi policy lock --install   # and pixi install --frozen once the check passes
pixi policy lock --restore   # and put the old pixi.lock back if the check fails
pixi policy lock -- --no-install   # arguments after -- go to pixi lock
```

By default a failing check leaves the new `pixi.lock` in place to look at, and exits 1 with the report; `--restore`
puts the one from before back. Nothing is installed after a failing check.

It is a convenience, not a gate: `pixi install`, `pixi run`, `pixi add` and the other commands that lock re-lock an
out-of-sync workspace without asking pixi-policy. The pre-commit hook and CI below are what keep a failing lockfile
out of the repository.

## A pre-commit hook

The published hook runs the check whenever `pixi.toml`, `pixi.lock`, `pyproject.toml` or `pixi-policy.toml` changes,
and stops a commit with an error finding:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aesir-oss/pixi-policy-pre-commit
    rev: v0.2.0
    hooks:
      - id: pixi-policy
```

Each tag of `aesir-oss/pixi-policy-pre-commit` installs the pixi-policy wheel of the same version from PyPI, so nothing
is compiled; `pre-commit autoupdate` moves `rev` to the newest release. The hook checks the workspace the way
`pixi policy` does from the repository root. `args:` passes any other flag: `args: [--manifest-path, app/pixi.toml]`
for a workspace below the root.

To run the version the workspace pins instead (the [pixi task](#a-pixi-task) above), a local hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pixi-policy
        name: pixi policy
        entry: pixi run policy
        language: system
        pass_filenames: false
        files: (^|/)(pixi\.toml|pixi\.lock|pyproject\.toml|pixi-policy\.toml)$
```

## GitHub Actions

The [GitHub Action](github-action.md) is one step: it installs the release binary, runs the check, fails the job on an
error finding and can upload the findings to code scanning.

```yaml
- uses: actions/checkout@v4
- uses: aesir-oss/pixi-policy-action@v0
  with:
    upload-sarif: "true"
```

The same by hand, with the version the workspace pins: write a SARIF report and upload it, so findings appear on the
pull request as code scanning annotations at the line in `pixi.toml`, `pixi.lock` or the policy. The check's exit code
fails the job; `if: always()` uploads the report even then.

```yaml
# .github/workflows/policy.yml
name: Policy
on: [pull_request]

jobs:
  policy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload-sarif
    steps:
      - uses: actions/checkout@v4
      - uses: prefix-dev/setup-pixi@v0.8.1
        with:
          environments: lint
      - name: Check the policy
        run: pixi run policy --format sarif --output policy.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: policy.sarif
          category: pixi-policy
```

Make the job a required status check, or a failing policy is only advice. Code scanning is free on public
repositories; private ones need GitHub code security. Without it, drop the upload and read the text report in the
job log.

## Other CI systems

Use the exit code to pass or fail the job, and `--format json --output policy.json` for anything that reads the
results: a dashboard, a comment bot, an artifact to keep. The [JSON report](output.md#json) has a published schema.

## When two machines disagree

A check that passes on a laptop and fails in CI, or reports `*.unavailable` on one network only, usually differs in
its environment rather than its policy. `pixi policy --version-details` prints the build and the settings a run would
use, with where each came from; paste it into an issue as it is (a proxy's password is masked):

```console
$ pixi policy --version-details
pixi-policy 0.4.0 (aarch64 macos)
pixi:      pixi 0.58.0 (PIXI_EXE)
cache:     /Users/me/Library/Caches/rattler/cache/pixi-policy (the platform cache directory; exists)
offline:   no
proxy:     http://proxy.example:3128 (HTTPS_PROXY)
no-proxy:  localhost,.internal
TLS:       the operating system's trust store (platform verifier)
overrides: PIXI_POLICY_OSV_URL=https://osv.mirror.example
schemas:   report 1, facts 1
```

`overrides` lists every `PIXI_POLICY_*_URL` that moves an upstream to a mirror; a forgotten one is a common cause.

`pixi policy doctor` goes further. After the same block, it asks each upstream the policy uses whether it answers
(`--all` asks every one), says what the caches hold, and checks the workspace:

```console
$ pixi policy doctor
...
Upstreams (those the policy uses; --all for every one):
  reachable OSV                 https://api.osv.dev: HTTP 404, 278 ms
  failed    CISA KEV            https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json: TLS: invalid peer certificate: UnknownIssuer
  ok        conda-PyPI mapping  https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json: HTTP 200, 528 ms

Caches in /Users/me/Library/Caches/rattler/cache/pixi-policy:
  advisories   116 files, newest 3h ago
  wheel-info   172 files, newest 2d ago

Workspace /Users/me/src/app:
  manifest  pixi.toml
  lockfile  pixi.lock, format 6
  policy    pixi-policy.toml
  extends   https://raw.githubusercontent.com/acme/policies/v3/base.toml (pinned; cached)
  in sync   yes

1 problem: CISA KEV is unreachable (TLS).
```

- **Upstreams.** `ok` and `reachable` both mean the host answered; `reachable` is a status of 400 or more from a
  service's base address, which is often not a page. A file that is not there (the KEV list, a VEX document, an
  extended policy) is `failed`. A failure names the layer: `DNS`, `proxy`, `TLS`, `timeout` or `connection`. With
  `PIXI_POLICY_OFFLINE`, nothing is asked and every upstream is `skipped`.
- **Caches.** Offline, a check can only use what is here; a cache's age says how old the data a check judges is.
- **Workspace.** `in sync` asks pixi, offline, whether pixi.lock still satisfies the manifest; when it does not,
  `check` is judging packages the manifest no longer asks for. Without pixi on `PATH`, it is `unknown`.

It exits 1 when an upstream the policy needs does not answer, pixi.lock is missing, unreadable or not current, or the
policy cannot be read, and 0 otherwise. It needs no workspace: outside one, it asks every upstream.

## Who owns the policy

Changing `pixi-policy.toml` changes what the workspace may contain, so review it like code: put it under
`CODEOWNERS`, so a new waiver or a loosened rule needs its owner's approval.
