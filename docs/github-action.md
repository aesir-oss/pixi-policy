# GitHub Action

`aesir-oss/pixi-policy-action` runs `pixi policy check` in a workflow: it downloads the release binary for the runner,
verifies its checksum, runs the check and fails the job when a finding is an error. pixi itself is not needed, though
with pixi on `PATH` (from `prefix-dev/setup-pixi`) the `lock.in-sync` rule also runs; without it, that check is a
warning.

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
      - uses: aesir-oss/pixi-policy-action@v0
        with:
          upload-sarif: "true"
```

The text report goes to the job log and the job summary. With `upload-sarif`, findings also appear on the pull request
as code scanning annotations at the line in `pixi.toml`, `pixi.lock` or the policy. Code scanning is free on public
repositories; private ones need GitHub code security. Make the job a required status check, or a failing policy is
only advice.

`@v0` follows the newest 0.x.y release. Pin an exact release (`@v0.2.0`) or a commit sha for a build that never
changes underneath you; `version` picks the binary independently of the ref.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `version` | the ref's | pixi-policy version to run: `@v0.2.0` runs 0.2.0, `@v0` the newest 0.x.y, a branch the newest release |
| `manifest-path` | nearest `pixi.toml` | The workspace's `pixi.toml` |
| `policy` | `pixi-policy.toml` beside it | The policy to check against |
| `fail-on-findings` | `true` | Fail the step on an error finding; with `false` it passes with a warning and `failed` says what happened |
| `summary` | `true` | Write the text report to the job summary |
| `upload-sarif` | `false` | Also write the report as SARIF and upload it to code scanning (needs `security-events: write`) |
| `sarif-category` | `pixi-policy` | Code scanning category for the upload |
| `json-output` | | Also write the [JSON report](output.md#json) to this path |
| `extra-args` | | Additional command-line arguments, whitespace separated |

A policy, manifest or lockfile that cannot be read (exit code 2) always fails the step, whatever `fail-on-findings`
says.

## Outputs

| Output | What it is |
|---|---|
| `version` | The pixi-policy version that ran |
| `failed` | `true` when at least one finding is an error |
| `sarif` | Path of the SARIF report, when `upload-sarif` is set |
| `json` | Path of the JSON report, when `json-output` is set |

## A workspace in a subdirectory

```yaml
- uses: aesir-oss/pixi-policy-action@v0
  with:
    manifest-path: services/api/pixi.toml
```

Paths in the SARIF report are relative to the job's working directory, the repository root, so annotations land on
the right files.

## A nightly re-check

When a waiver expires, the finding it waived fails the check again, with no commit to start a run. A scheduled run
catches it:

```yaml
on:
  pull_request:
  schedule:
    - cron: "0 6 * * *"
```

## Report without failing

```yaml
- uses: aesir-oss/pixi-policy-action@v0
  id: policy
  with:
    fail-on-findings: "false"
    json-output: policy.json
- if: steps.policy.outputs.failed == 'true'
  run: echo "the workspace fails its policy; see policy.json"
```
