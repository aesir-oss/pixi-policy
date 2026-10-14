//! `[freshness]` (#2), run offline against channel data recorded from conda.anaconda.org and the conda-forge bot:
//! setuptools 59.8.0 (25 majors behind, and its newer releases are noarch), jinja2 2.11.3 and old builds, and coreapi
//! and coreschema, whose feedstocks are archived. See `tests/fixtures/freshness/README.md`. Build ages grow every day,
//! so the assertions name packages rather than count them.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/freshness")
}

/// The fixture workspace with `policy`, checked offline against the recorded cache (or `cache`).
fn check(policy: &str, cache: Option<&Path>) -> assert_cmd::assert::Assert {
    let dir = tempfile::tempdir().unwrap();
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(fixture().join(file), dir.path().join(file)).unwrap();
    }
    std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    let recorded = fixture().join("cache");
    Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_POLICY_CACHE_DIR", cache.unwrap_or(&recorded))
        .env("PIXI_POLICY_OFFLINE", "1")
        .current_dir(dir.path())
        .args(["check", "--format", "json"])
        .assert()
}

fn findings(policy: &str) -> Vec<(String, String, String)> {
    let output = check(policy, None).get_output().stdout.clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["package"].as_str().unwrap_or_default().to_string(),
                f["message"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn packages<'a>(found: &'a [(String, String, String)], rule: &str) -> Vec<&'a str> {
    found
        .iter()
        .filter(|(r, _, _)| r == rule)
        .map(|(_, package, _)| package.as_str())
        .collect()
}

#[test]
fn an_archived_feedstock_fails_once_the_table_exists() {
    let found = findings("[freshness]\n");
    assert_eq!(packages(&found, "freshness.archived"), ["coreapi", "coreschema"]);
    let (_, _, message) = found.iter().find(|(_, p, _)| p == "coreapi").unwrap();
    assert_eq!(
        message,
        "its conda-forge feedstock coreapi-feedstock is archived, so it gets no more builds or fixes"
    );
    assert!(packages(&found, "freshness.build-age").is_empty());
    assert!(findings("[freshness]\narchived = false\n").is_empty());
}

#[test]
fn an_old_build_fails_by_the_time_the_lockfile_records() {
    let found = findings("[freshness]\narchived = false\nmax-build-age-days = 1095\n");
    let old = packages(&found, "freshness.build-age");
    for package in ["itypes", "jinja2", "markupsafe", "setuptools"] {
        assert!(old.contains(&package), "{package}: {old:?}");
    }
    let (_, _, message) = found.iter().find(|(_, p, _)| p == "itypes").unwrap();
    assert!(message.starts_with("built 2020-06-10, ") && message.ends_with("more than max-build-age-days (1095)"));
    assert!(findings("[freshness]\narchived = false\nmax-build-age-days = 100000\n").is_empty());
}

#[test]
fn a_package_far_behind_its_channels_newest_fails_and_noarch_counts() {
    let found = findings("[freshness]\narchived = false\nmax-majors-behind = 1\n");
    assert_eq!(packages(&found, "freshness.majors-behind"), ["setuptools"]);
    let (_, _, message) = &found[0];
    assert_eq!(
        message,
        "25 major versions behind 84.0.0, the newest in conda-forge, more than max-majors-behind (1)"
    );
    let strict = findings("[freshness]\narchived = false\nmax-majors-behind = 0\n");
    assert!(packages(&strict, "freshness.majors-behind").contains(&"jinja2"));
}

#[test]
fn no_channel_data_fails_the_check_but_build_ages_are_still_judged() {
    let empty = tempfile::tempdir().unwrap();
    check(
        "[freshness]\nmax-build-age-days = 1095\nmax-majors-behind = 1\n",
        Some(empty.path()),
    )
    .code(1)
    .stdout(
        contains("\"rule\": \"freshness.unavailable\"")
            .and(contains(
                "is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it",
            ))
            .and(contains("\"rule\": \"freshness.build-age\"")),
    );
}

#[test]
fn build_age_alone_needs_no_network() {
    let empty = tempfile::tempdir().unwrap();
    check(
        "[freshness]\narchived = false\nmax-build-age-days = 100000\n",
        Some(empty.path()),
    )
    .code(0);
    assert!(std::fs::read_dir(empty.path()).unwrap().next().is_none());
}
