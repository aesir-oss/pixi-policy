//! `[freshness] pypi` (#52), offline against PyPI release data recorded for the PyPI packages of
//! examples/projects/pixi/02-flask (`tests/fixtures/pypi`). Upload ages grow every day, so the assertions name packages
//! that are already old rather than count them.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The findings of an offline check of the flask example with `policy` against `cache`, as (rule, package, message).
fn findings(policy: &str, cache: &Path) -> Vec<(String, String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("pixi-policy.toml");
    std::fs::write(&file, policy).unwrap();
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_POLICY_OFFLINE", "1")
        .env("PIXI_POLICY_CACHE_DIR", cache)
        .arg("--manifest-path")
        .arg(root().join("examples/projects/pixi/02-flask/pixi.toml"))
        .args(["check", "--format", "json", "--policy"])
        .arg(&file)
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let field = |k: &str| f[k].as_str().unwrap_or("").to_string();
            (field("rule"), field("package"), field("message"))
        })
        .collect()
}

const POLICY: &str = "[freshness]\nmax-build-age-days = 1500\narchived = false\n";

#[test]
fn an_old_upload_fails_by_the_locked_files_upload_time() {
    let found = findings(POLICY, &root().join("tests/fixtures/pypi/cache"));
    for name in ["pytest", "pytest-flask", "py"] {
        let (_, _, message) = found
            .iter()
            .find(|(rule, package, _)| rule == "freshness.build-age" && package == name)
            .unwrap_or_else(|| panic!("{name}: {found:?}"));
        assert!(message.starts_with("uploaded to PyPI 20"), "{message}");
    }
    assert!(
        found
            .iter()
            .any(|(rule, package, m)| rule == "freshness.build-age" && package == "flask" && m.starts_with("built"))
    );
    assert!(
        !found
            .iter()
            .any(|(rule, ..)| rule == "freshness.unknown" || rule == "freshness.unavailable"),
        "{found:?}"
    );
}

#[test]
fn pypi_false_leaves_pypi_packages_out_and_missing_data_fails() {
    let found = findings(
        &format!("{POLICY}pypi = false\n"),
        &root().join("tests/fixtures/pypi/cache"),
    );
    assert!(!found.iter().any(|(_, package, _)| package == "pytest"), "{found:?}");
    let empty = tempfile::tempdir().unwrap();
    let found = findings(POLICY, empty.path());
    assert!(
        found.iter().any(|(rule, _, message)| rule == "freshness.unavailable"
            && message.contains("PyPI's release data for")
            && message.contains("PIXI_POLICY_OFFLINE")),
        "{found:?}"
    );
}
