Workspaces for the `lock.*` rules (#65), all built from `examples/projects/pixi/16-go-tools` (copied, so a regenerated
example does not change them): `in-sync` is the example as it is; `stale` adds a dependency to the manifest;
`missing-platform` adds `win-64`; `missing-environment` adds a `docs` environment; `missing-lockfile` has no
`pixi.lock`. Each keeps the original lockfile, so pixi's own `pixi list --locked` judges them as the tests expect.
