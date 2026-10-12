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

## A pre-commit hook

Run the check when the files it reads change:

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
        files: ^(pixi\.toml|pixi\.lock|pixi-policy\.toml)$
```

A published hook is planned ([#5](https://github.com/aesir-oss/pixi-policy/issues/5)).

## GitHub Actions

Write a SARIF report and upload it, so findings appear on the pull request as code scanning annotations at the line
in `pixi.toml`, `pixi.lock` or the policy. The check's exit code fails the job; `if: always()` uploads the report even
then.

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
job log. A packaged GitHub Action is planned ([#4](https://github.com/aesir-oss/pixi-policy/issues/4)).

## Other CI systems

Use the exit code to pass or fail the job, and `--format json --output policy.json` for anything that reads the
results: a dashboard, a comment bot, an artifact to keep. The [JSON report](output.md#json) has a published schema.

## Who owns the policy

Changing `pixi-policy.toml` changes what the workspace may contain, so review it like code: put it under
`CODEOWNERS`, so a new waiver or a loosened rule needs its owner's approval.
