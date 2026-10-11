# pixi-policy

Write down what your pixi environments are allowed to contain, and check it everywhere pixi runs: one
`pixi-policy.toml`, checked against `pixi.toml` and `pixi.lock`, failing with a clear reason and a fix hint.

```sh
pixi policy          # the same as `pixi policy check`
```

Planned and in progress: see the `pixi-policy 0.1.0` milestone in
[aesir-oss/pixi-ext-contrib](https://github.com/aesir-oss/pixi-ext-contrib). Part of pixi-ext-contrib, a community
project not affiliated with prefix.dev.
