//! `[advisories] vex` (#10), offline against the advisories fixture's recorded data: urllib3 1.26.4 from PyPI and
//! jinja2 3.1.2, a conda package looked up through conda-forge's mapping.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/advisories")
}

/// A CycloneDX VEX with one statement.
fn cyclonedx(id: &str, purl: &str, state: &str) -> String {
    format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{{"bom-ref":"p","purl":"{purl}"}}],
           "vulnerabilities":[{{"id":"{id}","affects":[{{"ref":"p"}}],
           "analysis":{{"state":"{state}","justification":"code_not_reachable","detail":"never parses cookies"}}}}]}}"#
    )
}

/// Check the fixture with `files` (the policy among them) written into the workspace; the output and exit code.
fn check(files: &[(&str, &str)], format: &str) -> (String, i32) {
    let dir = tempfile::tempdir().unwrap();
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(fixture().join(file), dir.path().join(file)).unwrap();
    }
    for (name, text) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_POLICY_CACHE_DIR", fixture().join("cache"))
        .env("PIXI_POLICY_OFFLINE", "1")
        .current_dir(dir.path())
        .args(["check", "--format", format])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap() + &String::from_utf8(output.stderr).unwrap();
    (text, output.status.code().unwrap())
}

fn json(files: &[(&str, &str)]) -> serde_json::Value {
    let (text, _) = check(files, "json");
    serde_json::from_str(&text).unwrap()
}

/// The advisories a report lists, as (rule, package, advisory id), failing or waived.
fn advisories(report: &serde_json::Value, list: &str) -> Vec<(String, String, String)> {
    report[list]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"].as_str().unwrap().starts_with("advisories."))
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["package"].as_str().unwrap().to_string(),
                f["advisory"][0].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

const POLICY: &str = "[advisories]\nvex = [\"security/vex.cdx.json\"]\n";

#[test]
fn a_not_affected_statement_waives_its_advisory_for_its_package() {
    let vex = cyclonedx("CVE-2023-43804", "pkg:pypi/urllib3@1.26.4", "not_affected");
    let files = [("pixi-policy.toml", POLICY), ("security/vex.cdx.json", vex.as_str())];
    let report = json(&files);
    let waived = report["waived"].as_array().unwrap();
    assert_eq!(waived.len(), 1, "{report:#}");
    assert_eq!(waived[0]["advisory"][0], "GHSA-v845-jxx5-vc9f", "matched by its alias");
    assert_eq!(
        waived[0]["vex"],
        serde_json::json!({
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "never parses cookies",
            "source": "vex.cdx.json",
        })
    );
    assert!(waived[0].get("waiver").is_none());
    assert!(
        !advisories(&report, "findings")
            .iter()
            .any(|(_, _, id)| id == "GHSA-v845-jxx5-vc9f")
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/pixi-policy-report.schema.json"))
            .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&report), "the report fits its schema");

    let (text, _) = check(&files, "text");
    assert!(
        text.contains("; VEX: not_affected (code_not_reachable), vex.cdx.json: never parses cookies\n"),
        "{text}"
    );
    let (sarif, _) = check(&files, "sarif");
    let sarif: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let suppressed: Vec<&serde_json::Value> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("suppressions").is_some())
        .collect();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(
        suppressed[0]["suppressions"][0]["properties"]["vex"]["state"],
        "not_affected"
    );
}

#[test]
fn a_statement_reaches_a_conda_package_through_its_pypi_identity() {
    let vex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
        {"vulnerability":{"name":"CVE-2024-56201"},"status":"fixed",
         "products":[{"@id":"pkg:pypi/jinja2@3.1.2"}]}]}"#;
    let report = json(&[
        ("pixi-policy.toml", "[advisories]\nvex = [\"jinja.openvex.json\"]\n"),
        ("jinja.openvex.json", vex),
    ]);
    let waived = advisories(&report, "waived");
    assert_eq!(
        waived,
        [(
            "advisories.vulnerable".to_string(),
            "jinja2".to_string(),
            "GHSA-gmj6-6f8f-6699".to_string()
        )]
    );
    assert_eq!(report["waived"][0]["vex"]["state"], "resolved");
}

#[test]
fn other_states_versions_and_packages_leave_the_finding_failing() {
    for vex in [
        cyclonedx("CVE-2023-43804", "pkg:pypi/urllib3@1.26.4", "in_triage"),
        cyclonedx("CVE-2023-43804", "pkg:pypi/urllib3@1.26.5", "not_affected"),
        cyclonedx("CVE-2023-43804", "pkg:pypi/requests", "not_affected"),
    ] {
        let (text, code) = check(&[("pixi-policy.toml", POLICY), ("security/vex.cdx.json", &vex)], "json");
        let report: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(report["waived"].as_array().unwrap().is_empty(), "{vex}");
        assert_eq!(code, 1);
    }
}

#[test]
fn a_shared_policy_carries_its_vex_relative_to_itself() {
    let vex = cyclonedx("GHSA-v845-jxx5-vc9f", "pkg:pypi/urllib3", "false_positive");
    let report = json(&[
        ("pixi-policy.toml", "[policy]\nextends = [\"shared/base.toml\"]\n"),
        ("shared/base.toml", POLICY),
        ("shared/security/vex.cdx.json", &vex),
    ]);
    assert_eq!(report["waived"].as_array().unwrap().len(), 1, "{report:#}");
}

#[test]
fn a_vex_that_cannot_be_used_is_an_error() {
    let (text, code) = check(&[("pixi-policy.toml", POLICY)], "text");
    assert_eq!(code, 2, "{text}");
    let shown = Path::new("security").join("vex.cdx.json").display().to_string();
    assert!(text.contains(&format!("cannot use the VEX {shown}")), "{text}");
    let (text, code) = check(
        &[
            ("pixi-policy.toml", POLICY),
            ("security/vex.cdx.json", "{\"spdxVersion\":\"SPDX-2.3\"}"),
        ],
        "text",
    );
    assert_eq!(code, 2);
    assert!(text.contains("neither a CycloneDX"), "{text}");
    let (text, code) = check(
        &[(
            "pixi-policy.toml",
            "[advisories]\nvex = [\"https://example.com/main/vex.json\"]\n",
        )],
        "text",
    );
    assert_eq!(code, 2);
    assert!(text.contains("not a pinned"), "{text}");
}
