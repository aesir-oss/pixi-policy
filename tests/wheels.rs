//! PyPI licenses from the locked wheels' METADATA (#51), offline against METADATA recorded from pypi.org for the PyPI
//! packages of examples/projects/pixi/02-flask (`tests/fixtures/wheels/cache`).

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The JSON report of an offline check of the flask example with `policy`, against `cache`.
fn report(policy: &str, cache: &Path) -> serde_json::Value {
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
    serde_json::from_slice(&output.stdout).unwrap()
}

fn pypi_findings(report: &serde_json::Value) -> Vec<(String, String, String)> {
    let pypi = [
        "pytest",
        "pytest-flask",
        "pluggy",
        "iniconfig",
        "packaging",
        "attrs",
        "py",
        "tomli",
    ];
    let mut out: Vec<(String, String, String)> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| pypi.contains(&f["package"].as_str().unwrap_or("")))
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["package"].as_str().unwrap().to_string(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[test]
fn a_wheels_license_is_judged_like_a_conda_packages() {
    let found = pypi_findings(&report(
        "[licenses]\nallow = [\"MIT\"]\n",
        &root().join("tests/fixtures/wheels/cache"),
    ));
    assert_eq!(
        found,
        [(
            "licenses.not-allowed".to_string(),
            "packaging".to_string(),
            "license Apache-2.0 OR BSD-2-Clause cannot be satisfied with the allowed licenses".to_string()
        )],
        "every other PyPI package is MIT, by License-Expression, License or a classifier"
    );
    let found = pypi_findings(&report(
        "[licenses]\nallow = [\"BSD-3-Clause\"]\n",
        &root().join("tests/fixtures/wheels/cache"),
    ));
    assert!(
        found
            .iter()
            .any(|(rule, package, message)| rule == "licenses.not-allowed"
                && package == "py"
                && message
                    == "license MIT (its METADATA says \"MIT license\") cannot be satisfied with the allowed licenses"),
        "{found:?}"
    );
}

#[test]
fn an_or_accepted_only_through_review_needs_a_review() {
    // #60: packaging's METADATA says Apache-2.0 OR BSD-2-Clause; BSD-2-Clause is not allowed, so it needs Apache-2.0.
    let found = pypi_findings(&report(
        "[licenses]\nallow = [\"MIT\"]\nreview = [\"Apache-2.0\"]\n",
        &root().join("tests/fixtures/wheels/cache"),
    ));
    assert_eq!(
        found,
        [(
            "licenses.review".to_string(),
            "packaging".to_string(),
            "license Apache-2.0 OR BSD-2-Clause needs a review".to_string()
        )]
    );
}

#[test]
fn without_the_metadata_a_pypi_package_is_unknown_and_says_why() {
    let empty = tempfile::tempdir().unwrap();
    let found = pypi_findings(&report("[licenses]\n", empty.path()));
    assert_eq!(found.len(), 8, "{found:?}");
    assert!(
        found.iter().all(|(rule, _, message)| rule == "licenses.unknown"
            && message.ends_with("its METADATA is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it")),
        "{found:?}"
    );
}
