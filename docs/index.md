# pixi-policy

Write down what your pixi environments are allowed to contain, and check it everywhere pixi runs: one
`pixi-policy.toml`, checked against `pixi.toml` and `pixi.lock`, failing with a clear reason and a fix hint.

```sh
pixi policy init     # write a policy the workspace passes today
pixi policy          # check it (the same as `pixi policy check`)
pixi policy explain  # every rule, its keys and an example
```

The full guide, the policy key reference and the rule catalog are being written for 0.1.0 (#70). Until then,
`pixi policy explain <RULE>` describes each rule, and [License policy](licenses.md) covers the `[licenses]` table.
