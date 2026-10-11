//! The command line, run as a user would: exit codes, the report and the diagnostics. Diagnostics are matched by
//! code, since miette wraps their text to the terminal's width.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// A workspace with a real lockfile and, when given, a policy.
fn workspace(policy: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../pixi-sbom/tests/fixtures/with-pypi/pixi.lock");
    std::fs::copy(lock, dir.path().join("pixi.lock")).unwrap();
    std::fs::write(dir.path().join("pixi.toml"), "[workspace]\nname = \"w\"\n").unwrap();
    if let Some(policy) = policy {
        std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    }
    dir
}

fn policy() -> Command {
    let mut cmd = Command::cargo_bin("pixi-policy").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

#[test]
fn a_policy_with_nothing_to_find_passes_and_says_what_it_checked() {
    let ws = workspace(Some(""));
    for args in [&[][..], &["check"][..]] {
        policy()
            .current_dir(ws.path())
            .args(args)
            .assert()
            .code(0)
            .stdout(contains("0 errors, 0 warnings, 0 waived in ").and(contains(" across ")));
    }
}

#[test]
fn the_workspace_is_found_from_below_or_named() {
    let ws = workspace(Some(""));
    let inner = ws.path().join("src");
    std::fs::create_dir(&inner).unwrap();
    policy().current_dir(&inner).assert().code(0);
    policy()
        .arg("--manifest-path")
        .arg(ws.path().join("pixi.toml"))
        .assert()
        .code(0);
}

#[test]
fn a_policy_elsewhere_is_read_with_policy() {
    let ws = workspace(None);
    let other = ws.path().join("strict.toml");
    std::fs::write(&other, "[bans]\n").unwrap();
    policy()
        .current_dir(ws.path())
        .arg("--policy")
        .arg(&other)
        .assert()
        .code(0);
}

#[test]
fn no_policy_is_an_error_not_a_pass() {
    let ws = workspace(None);
    policy()
        .current_dir(ws.path())
        .assert()
        .code(2)
        .stdout("")
        .stderr(contains("pixi_policy::policy::missing"));
}

#[test]
fn an_unknown_key_is_shown_where_it_is() {
    let ws = workspace(Some("[sources]\n\n[nope]\nx = 1\n"));
    policy().current_dir(ws.path()).assert().code(2).stderr(
        contains("pixi_policy::policy::parse")
            .and(contains("[nope]"))
            .and(contains("here")),
    );
}

#[test]
fn no_workspace_or_no_lockfile_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    policy()
        .arg("--manifest-path")
        .arg(dir.path().join("pixi.toml"))
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::workspace::manifest"));
    std::fs::write(dir.path().join("pixi.toml"), "").unwrap();
    policy()
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::workspace::no_lockfile").and(contains("pixi lock")));
}

#[test]
fn a_damaged_lockfile_is_an_error() {
    let ws = workspace(Some(""));
    std::fs::write(ws.path().join("pixi.lock"), "version: [").unwrap();
    policy()
        .current_dir(ws.path())
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::lockfile::parse"));
}

/// Every example workspace the docs and pixi-sbom's tests use: an empty policy reads all of it and passes.
#[test]
fn every_example_workspace_is_checked() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/projects/pixi");
    let empty = tempfile::NamedTempFile::new().unwrap();
    let mut seen = 0;
    for entry in std::fs::read_dir(&examples).unwrap() {
        let manifest = entry.unwrap().path().join("pixi.toml");
        if !manifest.is_file() {
            continue;
        }
        seen += 1;
        let output = policy()
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--policy")
            .arg(empty.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}: {stdout}{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.starts_with("0 errors, 0 warnings, 0 waived in ") && !stdout.contains(" in 0 packages"),
            "{}: {stdout}",
            manifest.display()
        );
    }
    assert!(seen >= 19, "found {seen} example workspaces");
}

#[test]
fn a_pyproject_workspace_is_found() {
    let ws = workspace(Some(""));
    std::fs::remove_file(ws.path().join("pixi.toml")).unwrap();
    std::fs::write(
        ws.path().join("pyproject.toml"),
        "[tool.pixi.workspace]\nchannels = []\n",
    )
    .unwrap();
    policy().current_dir(ws.path()).assert().code(0);
}

fn validator(file: &str) -> jsonschema::Validator {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    let schema: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    jsonschema::options().offline().build(&schema).unwrap()
}

#[test]
fn json_and_sarif_match_their_schemas() {
    let ws = workspace(Some(""));
    for (format, schema) in [
        ("json", "schemas/pixi-policy-report.schema.json"),
        ("sarif", "../pixi-sbom/tests/schemas/sarif-schema-2.1.0.json"),
    ] {
        let output = policy()
            .current_dir(ws.path())
            .args(["--format", format])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{format}");
        let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let errors: Vec<String> = validator(schema).iter_errors(&doc).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{format}: {errors:#?}");
    }
    let output = policy()
        .current_dir(ws.path())
        .args(["check", "--format", "json"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        doc["workspace"]["lockfile"], "pixi.lock",
        "relative to the working directory"
    );
    assert_eq!(doc["summary"]["passed"], true);
}

#[test]
fn output_writes_a_file_without_colour_unless_always() {
    let ws = workspace(Some(""));
    let report = ws.path().join("report.txt");
    policy()
        .current_dir(ws.path())
        .env_remove("NO_COLOR")
        .arg("--output")
        .arg(&report)
        .assert()
        .code(0)
        .stdout("");
    let text = std::fs::read_to_string(&report).unwrap();
    assert!(text.starts_with("0 errors") && !text.contains('\u{1b}'), "{text:?}");
    policy()
        .current_dir(ws.path())
        .args(["--color", "always", "--output"])
        .arg(&report)
        .assert()
        .code(0);
    assert!(std::fs::read_to_string(&report).unwrap().contains('\u{1b}'));
}

#[test]
fn an_unwritable_output_is_an_error() {
    let ws = workspace(Some(""));
    policy()
        .current_dir(ws.path())
        .arg("--output")
        .arg(ws.path().join("missing-dir/report.json"))
        .assert()
        .code(2)
        .stderr(contains("cannot write the report"));
}

#[test]
fn an_unknown_format_is_a_usage_error() {
    policy()
        .args(["--format", "xml"])
        .assert()
        .code(2)
        .stderr(contains("invalid value 'xml'").and(contains("text, json, sarif")));
}

/// The sources fixture: one package from every kind of origin (#61).
fn sources_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources")
}

const STRICT_SOURCES: &str = r#"[sources]
allowed-channels = ["conda-forge", "https://conda.acme.internal/prod"]
allowed-indexes = ["https://pypi.org/simple", "https://pypi.acme.internal/simple"]
allow-git = false
allow-url = false
allow-path = false
"#;

#[test]
fn a_failing_sources_policy_exits_1_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let policy_file = dir.path().join("pixi-policy.toml");
    std::fs::write(&policy_file, STRICT_SOURCES).unwrap();
    let manifest = sources_fixture().join("pixi.toml");
    let output = policy()
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("error[sources.channels] samtools 1.21: comes from channel https://conda.anaconda.org/bioconda/"),
        "{text}"
    );
    assert!(
        text.contains("error[sources.indexes] typosquat 1.0: comes from index https://evil.example/simple"),
        "{text}"
    );
    assert!(
        text.ends_with("8 errors, 0 warnings, 0 waived in 13 packages across 1 environment-platform pair\n"),
        "{text}"
    );

    let output = policy()
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_file)
        .args(["--format", "sarif"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let errors: Vec<String> = validator("../pixi-sbom/tests/schemas/sarif-schema-2.1.0.json")
        .iter_errors(&doc)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 8);
    assert_eq!(
        doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(),
        pixi_policy::check::rules().len()
    );
}

#[test]
fn a_ban_fails_a_real_workspace_and_names_the_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let policy_file = dir.path().join("pixi-policy.toml");
    std::fs::write(
        &policy_file,
        "[bans]\ndeny = [{ name = \"django\", version = \"<6\", reason = \"too old\", use-instead = \"django 6\" }]\n",
    )
    .unwrap();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/projects/pixi/01-django/pixi.toml");
    let output = policy()
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_file)
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        text.contains("error[bans.deny] django ") && text.contains("is banned (version <6): too old"),
        "{text}"
    );
    assert!(text.contains("= help: use django 6 instead"), "{text}");
}

#[test]
fn a_ban_that_cannot_be_compiled_exits_2() {
    let ws = workspace(Some("[bans]\ndeny = [{ name = \"openssl\", version = \"<1.1.1w\" }]\n"));
    policy()
        .current_dir(ws.path())
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::policy::invalid").and(contains("kind")));
}

#[test]
fn a_license_policy_fails_a_real_workspace_with_errors_and_review_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let policy_file = dir.path().join("pixi-policy.toml");
    std::fs::write(
        &policy_file,
        "[licenses]\nreview = [\"LGPL-*\"]\ndeny = [\"GPL-3.0-only\"]\nunknown = \"allow\"\n",
    )
    .unwrap();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/projects/pixi/02-flask/pixi.toml");
    let output = policy()
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy_file)
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        text.contains("error[licenses.deny] ")
            && text.contains("license GPL-3.0-only cannot be satisfied without a denied license"),
        "{text}"
    );
    assert!(
        text.contains("warning[licenses.review] ") && text.contains("license LGPL-2.1-only needs a review"),
        "{text}"
    );
    assert!(!text.contains("licenses.unknown"), "{text}");
}

#[test]
fn help_names_the_pixi_command() {
    policy()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(contains("Usage: pixi policy").and(contains("--policy <FILE>")));
}
