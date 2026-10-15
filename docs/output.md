# Output formats

`--format` picks the report: `text` (the default), `json` or `sarif`. `--output <file>` writes it to a file instead
of standard output. Whatever the format, the exit code is the verdict.

| Code | Meaning |
|---|---|
| 0 | Nothing failed. Warnings may still be reported |
| 1 | At least one finding is an error |
| 2 | The policy, the manifest or the lockfile could not be read |

## Text

For people, in a terminal or a CI log. Findings are grouped by severity, each with its rule, the package, where it
was found and a fix hint, then a summary line:

```text
error[bans.deny] openssl 3.6.4: is banned (version <3): EOL
  --> pixi.lock: environment "default", linux-64
  = help: use libressl instead

1 error, 0 warnings, 0 waived in 1644 packages across 30 environment-platform pairs
```

`--color auto` (the default) colours it when standard output is a terminal and the environment does not forbid it;
`always` colours it even when redirected (for `less -R` or a CI log), and `never` turns colour off. A report written
with `--output` is never coloured unless `--color always`.

## JSON

For scripts and dashboards: one object per finding with stable field names, the waived findings with their waivers,
and a summary.

```json
{
  "version": 1,
  "tool": { "name": "pixi-policy", "version": "0.1.0" },
  "workspace": { "manifest": "pixi.toml", "lockfile": "pixi.lock", "policy": "pixi-policy.toml" },
  "summary": { "passed": false, "errors": 1, "warnings": 0, "waived": 0, "packages": 1644, "targets": 30 },
  "findings": [
    {
      "rule": "bans.deny",
      "severity": "error",
      "package": "openssl",
      "version": "3.6.4",
      "environment": "default",
      "platform": "linux-64",
      "file": "pixi.lock",
      "line": null,
      "message": "is banned (version <3): EOL",
      "help": "use libressl instead"
    }
  ],
  "waived": []
}
```

The schema is [pixi-policy-report.schema.json](schemas/pixi-policy-report.schema.json). For the packages themselves
rather than the findings, as input for another policy engine, see [Facts for OPA and Rego](rego.md). Fields may be added within
`version` 1; renaming or removing one raises the version.

## SARIF

SARIF 2.1.0, for GitHub code scanning and other SARIF viewers: one rule per rule ID, with the
[rule catalog](rules.md)'s text as its help, and one result per finding at its file and line. Waived findings are
included as suppressed results, so a viewer can show what was waived and why. [In development and CI](ci.md#github-actions)
shows the upload.
