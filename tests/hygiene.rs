//! `[hygiene]` (#11), offline, against a lockfile edited to hold PyPI duplicates of conda packages: msgpack beside conda
//! msgpack-python (named by pixi.lock's purls), and pyyaml beside a conda pyyaml pixi.lock states no purls for (named
//! by conda-forge's mapping). See `tests/fixtures/hygiene/README.md`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// The findings of an offline check of fixture `name` with `policy` and `cache`, as (rule, package), and the exit code.
fn findings(name: &str, policy: &str, cache: &Path) -> (Vec<(String, String)>, i32) {
    let dir = tempfile::tempdir().unwrap();
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(fixture(name).join(file), dir.path().join(file)).unwrap();
    }
    std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_POLICY_CACHE_DIR", cache)
        .env("PIXI_POLICY_OFFLINE", "1")
        .current_dir(dir.path())
        .args(["check", "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let found = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["package"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    (found, output.status.code().unwrap())
}

fn pair(rule: &str, package: &str) -> (String, String) {
    (rule.into(), package.into())
}

#[test]
fn a_pypi_package_a_conda_package_provides_fails() {
    let (found, code) = findings("hygiene", "[hygiene]\n", &fixture("hygiene/cache"));
    assert_eq!(
        found,
        [
            pair("hygiene.conda-pypi-duplicate", "msgpack"),
            pair("hygiene.conda-pypi-duplicate", "pyyaml"),
        ]
    );
    assert_eq!(code, 1);
}

#[test]
fn without_the_mapping_the_stated_purls_still_count_and_the_check_fails() {
    let empty = tempfile::tempdir().unwrap();
    let (found, code) = findings("hygiene", "[hygiene]\n", empty.path());
    assert_eq!(
        found,
        [
            pair("hygiene.conda-pypi-duplicate", "msgpack"),
            pair("hygiene.unavailable", ""),
        ]
    );
    assert_eq!(code, 1);
}

#[test]
fn the_mapping_is_read_only_when_an_environment_needs_it() {
    let empty = tempfile::tempdir().unwrap();
    let (found, code) = findings("python", "[hygiene]\n", empty.path());
    assert!(found.is_empty() && code == 0, "no PyPI packages: {found:?}");
    let (found, code) = findings("hygiene", "[hygiene]\nconda-pypi-duplicate = false\n", empty.path());
    assert!(found.is_empty() && code == 0, "turned off: {found:?}");
}
