//! `[python]` (#42) against a workspace whose environments lock Python 3.12, 3.13 and 3.14 on linux-64 and osx-arm64,
//! and one environment without Python.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// A finding: rule, severity, environment, platform and Python version.
type Row = (String, String, String, String, String);

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python")
}

/// The findings a check of the fixture with `policy` reports, as (rule, severity, environment, platform, version),
/// and its exit code.
fn findings(policy: &str) -> (Vec<Row>, i32) {
    let dir = tempfile::tempdir().unwrap();
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(fixture().join(file), dir.path().join(file)).unwrap();
    }
    std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .current_dir(dir.path())
        .args(["check", "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let field = |finding: &serde_json::Value, name: &str| finding[name].as_str().unwrap_or("").to_string();
    let found = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                field(f, "rule"),
                field(f, "severity"),
                field(f, "environment"),
                field(f, "platform"),
                field(f, "version"),
            )
        })
        .collect();
    (found, output.status.code().unwrap())
}

fn row(rule: &str, severity: &str, environment: &str, platform: &str, version: &str) -> Row {
    (
        rule.into(),
        severity.into(),
        environment.into(),
        platform.into(),
        version.into(),
    )
}

#[test]
fn older_fails_and_newer_warns_on_every_platform() {
    let (found, code) = findings("[python]\nversion = \"3.13\"\n");
    assert_eq!(
        found,
        [
            row("python.older", "error", "old", "linux-64", "3.12.15"),
            row("python.older", "error", "old", "osx-arm64", "3.12.15"),
            row("python.newer", "warning", "new", "linux-64", "3.14.8"),
            row("python.newer", "warning", "new", "osx-arm64", "3.14.8"),
        ]
    );
    assert_eq!(code, 1);
}

#[test]
fn every_patch_release_of_the_standard_passes() {
    let (found, _) = findings("[python]\nversion = \"3.14\"\nolder = \"warn\"\n");
    assert!(found.iter().all(|f| f.0 == "python.older" && f.2 != "new"), "{found:?}");
    assert_eq!(found.len(), 4, "3.12 and 3.13 on two platforms: {found:?}");
    let (_, code) = findings("[python]\nversion = \"3.14\"\nolder = \"warn\"\n");
    assert_eq!(code, 0, "warnings do not fail");
}

#[test]
fn severities_follow_the_policy() {
    let (found, code) = findings("[python]\nversion = \"3.13\"\nolder = \"allow\"\nnewer = \"error\"\n");
    assert_eq!(
        found,
        [
            row("python.newer", "error", "new", "linux-64", "3.14.8"),
            row("python.newer", "error", "new", "osx-arm64", "3.14.8"),
        ]
    );
    assert_eq!(code, 1);
    let (found, code) = findings("[python]\nversion = \"3.13\"\nolder = \"allow\"\nnewer = \"allow\"\n");
    assert!(found.is_empty() && code == 0, "{found:?}");
}

#[test]
fn a_waiver_lets_an_environment_through() {
    let policy = "[python]\nversion = \"3.13\"\nnewer = \"allow\"\n\n[[waivers]]\nrule = \"python.older\"\npackage = \
                  \"python\"\nreason = \"migrating\"\nexpires = 2099-01-01\n";
    let (found, code) = findings(&format!("max-waiver-days = 0\n{policy}"));
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(code, 0);
}
