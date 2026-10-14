# pixi-policy action

A GitHub Action that checks a pixi workspace's `pixi.toml` and `pixi.lock` against its `pixi-policy.toml`: where
packages may come from, banned packages and versions, licenses, and manifest and lockfile hygiene. It downloads the
[pixi-policy](https://github.com/aesir-oss/pixi-policy) release binary for the runner, verifies its checksum, runs the
check and fails the job on an error finding. pixi itself is not needed, though with pixi on `PATH` the
`lock.in-sync` rule also runs.

```yaml
permissions:
  contents: read
  security-events: write   # upload-sarif
steps:
  - uses: actions/checkout@v4
  - uses: aesir-oss/pixi-policy-action@v0
    with:
      upload-sarif: "true"
```

`@v0` follows the newest 0.x.y release. Pin an exact release (`@v0.2.0`) or a commit sha for a build that never
changes underneath you.

Every input and output, and more examples, are in the
[GitHub Action guide](https://aesir-oss.github.io/pixi-policy/latest/github-action/).

This repository is published from
[`actions/pixi-policy`](https://github.com/aesir-oss/pixi-policy/tree/main/actions/pixi-policy) in
[aesir-oss/pixi-policy](https://github.com/aesir-oss/pixi-policy) on each release; issues and changes go there.

## License

[Apache-2.0](LICENSE)
