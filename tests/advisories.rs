//! `[advisories]` (#3), run offline against advisory data recorded from OSV, CISA and FIRST: jinja2 3.1.2 (a conda
//! package the lockfile states no PyPI purl for, so the conda-forge mapping names it) and urllib3 1.26.4 from PyPI.
//! See `tests/fixtures/advisories/README.md`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/advisories")
}

/// The fixture workspace with `policy`, checked offline against the recorded cache (or `cache`).
fn check(policy: &str, cache: Option<&Path>, format: &str) -> assert_cmd::assert::Assert {
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
        .args(["check", "--format", format])
        .assert()
}

fn report(policy: &str) -> serde_json::Value {
    let output = check(policy, None, "json").get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

fn findings<'a>(report: &'a serde_json::Value, rule: &str) -> Vec<&'a serde_json::Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == rule)
        .collect()
}

#[test]
fn high_advisories_fail_with_the_fixed_version_and_conda_packages_are_found_through_the_mapping() {
    check("[advisories]\n", None, "text").code(1).stdout(
        contains("error[advisories.vulnerable] urllib3 1.26.4: GHSA-v845-jxx5-vc9f (CVE-2023-43804), high severity")
            .and(contains(
                "= help: upgrade to 1.26.17 or later; see https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f",
            ))
            .and(contains(
                "error[advisories.vulnerable] jinja2 3.1.2: GHSA-gmj6-6f8f-6699 (CVE-2024-56201)",
            ))
            .and(contains("10 errors, 0 warnings")),
    );
    let report = report("[advisories]\n");
    let urllib3 = findings(&report, "advisories.vulnerable")
        .into_iter()
        .find(|f| f["advisory"][0] == "GHSA-v845-jxx5-vc9f")
        .unwrap();
    let names: Vec<&str> = urllib3["advisory"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"CVE-2023-43804") && names.contains(&"PYSEC-2023-192"),
        "{names:?}"
    );
}

#[test]
fn fail_on_and_epss_move_the_line() {
    let medium = report("[advisories]\nfail-on = \"medium\"\n");
    assert!(findings(&medium, "advisories.vulnerable").len() > 10);
    let critical = report("[advisories]\nfail-on = \"critical\"\n");
    assert!(findings(&critical, "advisories.vulnerable").is_empty());
    assert_eq!(critical["summary"]["passed"], true);
    let epss = report("[advisories]\nfail-on = \"critical\"\nepss = 0.03\n");
    let hits = findings(&epss, "advisories.vulnerable");
    assert_eq!(hits.len(), 1, "{hits:?}");
    let message = hits[0]["message"].as_str().unwrap();
    assert!(
        message.starts_with("GHSA-q2q7-5pp4-w6pg (CVE-2021-33503), EPSS 0.03273"),
        "{message}"
    );
}

#[test]
fn without_the_mapping_a_conda_package_the_lockfile_names_no_purl_for_is_not_looked_up() {
    let lock_only = report("[advisories]\npypi-mapping = \"lock\"\n");
    let packages: Vec<&str> = findings(&lock_only, "advisories.vulnerable")
        .iter()
        .map(|f| f["package"].as_str().unwrap())
        .collect();
    assert!(
        !packages.is_empty() && packages.iter().all(|p| *p == "urllib3"),
        "{packages:?}"
    );
}

#[test]
fn a_waiver_takes_one_advisory_by_any_alias_or_every_advisory_on_the_package() {
    let waiver = |advisory: &str| {
        format!(
            "max-waiver-days = 0\n[advisories]\n[[waivers]]\nrule = \"advisories.vulnerable\"\npackage = \"urllib3\"\n\
             {advisory}reason = \"r\"\nexpires = 2099-01-01\n"
        )
    };
    let one = report(&waiver("advisory = \"cve-2023-43804\"\n"));
    assert_eq!(one["waived"].as_array().unwrap().len(), 1);
    assert_eq!(one["waived"][0]["advisory"][0], "GHSA-v845-jxx5-vc9f");
    let all = report(&waiver(""));
    assert_eq!(all["waived"].as_array().unwrap().len(), 8);
    assert!(
        findings(&all, "advisories.vulnerable")
            .iter()
            .all(|f| f["package"] == "jinja2")
    );
}

#[test]
fn no_advisory_data_fails_the_check() {
    let empty = tempfile::tempdir().unwrap();
    check("[advisories]\n", Some(empty.path()), "text").code(1).stdout(
        contains("error[advisories.unavailable] no package could be checked for advisories").and(contains(
            "the conda-forge PyPI mapping is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it",
        )),
    );
}

#[test]
fn without_the_table_nothing_is_looked_up() {
    let empty = tempfile::tempdir().unwrap();
    check("", Some(empty.path()), "text").code(0);
    assert!(std::fs::read_dir(empty.path()).unwrap().next().is_none());
}
