//! `pixi policy facts` (#9): the document fits its schema for every example workspace, and the Rego example's expected
//! findings (examples/rego/flask/expected.json, which `pixi run -e rego rego-test` checks the Rego against) are the
//! ones pixi-policy's built-in rules give for the same settings.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str], manifest: &Path) -> std::process::Output {
    Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_POLICY_OFFLINE", "1")
        .env(
            "PIXI_POLICY_CACHE_DIR",
            std::env::temp_dir().join("pixi-policy-tests-no-cache"),
        )
        .arg("--manifest-path")
        .arg(manifest)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_facts_of_every_example_fit_the_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root().join("schemas/pixi-policy-facts.schema.json")).unwrap())
            .unwrap();
    let validator = jsonschema::options().offline().build(&schema).unwrap();
    let mut manifests: Vec<PathBuf> = std::fs::read_dir(root().join("examples/projects/pixi"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("pixi.toml"))
        .collect();
    manifests.push(root().join("tests/fixtures/sources/pixi.toml"));
    manifests.sort();
    for manifest in &manifests {
        let output = run(&["facts"], manifest);
        assert!(
            output.status.success(),
            "{}: {}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&doc)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{}: {errors:?}", manifest.display());
        assert!(!doc["environments"].as_array().unwrap().is_empty());
    }
}

#[test]
fn facts_write_json_only() {
    let manifest = root().join("examples/projects/pixi/02-flask/pixi.toml");
    let json = run(&["facts", "--format", "json"], &manifest);
    assert!(json.status.success());
    let sarif = run(&["facts", "--format", "sarif"], &manifest);
    assert_eq!(sarif.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&sarif.stderr).contains("writes JSON only"));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("facts.json");
    let written = run(&["facts", "--output", file.to_str().unwrap()], &manifest);
    assert!(written.status.success() && written.stdout.is_empty());
    assert_eq!(std::fs::read(&file).unwrap(), json.stdout);
}

#[test]
fn the_rego_example_expects_what_the_built_in_rules_find() {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("pixi-policy.toml");
    std::fs::write(
        &policy,
        "[sources]\nallowed-channels = [\"conda-forge\"]\n\n[bans]\ndeny = [{ name = \"py\" }]\n\n[licenses]\n\
         deny = [\"GPL-3.0-only\"]\nunknown = \"allow\"\nambiguous = \"allow\"\n",
    )
    .unwrap();
    let manifest = root().join("examples/projects/pixi/02-flask/pixi.toml");
    let output = run(
        &["check", "--format", "json", "--policy", policy.to_str().unwrap()],
        &manifest,
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let key = |f: &serde_json::Value| {
        ["rule", "package", "environment", "platform"].map(|k| f[k].as_str().unwrap().to_string())
    };
    let mut found: Vec<[String; 4]> = report["findings"].as_array().unwrap().iter().map(key).collect();
    found.sort();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root().join("examples/rego/flask/expected.json")).unwrap())
            .unwrap();
    let mut expected: Vec<[String; 4]> = expected["expected"].as_array().unwrap().iter().map(key).collect();
    expected.sort();
    assert_eq!(found, expected);
}
