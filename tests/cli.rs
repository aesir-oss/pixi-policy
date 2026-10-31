//! The command line, run as a user would: exit codes, the report and the diagnostics. Diagnostics are matched by
//! code, since miette wraps their text to the terminal's width.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// A workspace with a real lockfile and, when given, a policy.
fn workspace(policy: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with-pypi/pixi.lock");
    std::fs::copy(lock, dir.path().join("pixi.lock")).unwrap();
    std::fs::write(dir.path().join("pixi.toml"), "[workspace]\nname = \"w\"\n").unwrap();
    if let Some(policy) = policy {
        std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    }
    dir
}

/// The binary, offline with an empty cache, so no test reads a wheel's license from PyPI.
fn policy() -> Command {
    let mut cmd = Command::cargo_bin("pixi-policy").unwrap();
    cmd.env("NO_COLOR", "1").env("PIXI_POLICY_OFFLINE", "1").env(
        "PIXI_POLICY_CACHE_DIR",
        std::env::temp_dir().join("pixi-policy-tests-no-cache"),
    );
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
    std::fs::write(dir.path().join("pixi-policy.toml"), "").unwrap();
    policy()
        .current_dir(dir.path())
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::workspace::no_lockfile").and(contains("pixi lock")));
}

/// A lock fixture (#65), and a policy beside it in a temporary directory.
fn lock_fixture(name: &str, policy_text: &str) -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("pixi-policy.toml"), policy_text).unwrap();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lock")
        .join(name)
        .join("pixi.toml");
    (manifest, dir)
}

#[test]
fn with_lock_rules_a_missing_lockfile_is_a_finding_not_an_input_error() {
    let (manifest, dir) = lock_fixture("missing-lockfile", "[lock]\n");
    let output = policy()
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--policy")
        .arg(dir.path().join("pixi-policy.toml"))
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        text.starts_with("error[lock.present] the workspace has no pixi.lock\n  --> pixi.lock\n"),
        "{text}"
    );
    assert!(
        text.ends_with("1 error, 0 warnings, 0 waived in 0 packages across 0 environment-platform pairs\n"),
        "{text}"
    );
}

#[test]
fn lock_rules_judge_the_fixtures_as_pixi_does() {
    for (name, expected_code, expected) in [
        ("in-sync", 0, None),
        (
            "stale",
            1,
            Some("error[lock.in-sync] pixi.lock does not satisfy the manifest any more"),
        ),
        (
            "missing-platform",
            1,
            Some(
                "error[lock.complete] environment default is not locked for win-64\n  --> pixi.lock: environment \"default\", win-64\n",
            ),
        ),
        (
            "missing-environment",
            1,
            Some("error[lock.complete] environment docs is not in pixi.lock\n  --> pixi.lock: environment \"docs\"\n"),
        ),
    ] {
        let (manifest, dir) = lock_fixture(name, "[lock]\n");
        let output = policy()
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--policy")
            .arg(dir.path().join("pixi-policy.toml"))
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(expected_code), "{name}: {text}");
        if let Some(expected) = expected {
            assert!(text.contains(expected), "{name}: {text}");
        }
    }
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
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi");
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
        ("sarif", "tests/schemas/sarif-schema-2.1.0.json"),
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
    let errors: Vec<String> = validator("tests/schemas/sarif-schema-2.1.0.json")
        .iter_errors(&doc)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 8);
    assert_eq!(
        doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(),
        pixi_policy::explain::catalog().len()
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
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi/01-django/pixi.toml");
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
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi/02-flask/pixi.toml");
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

/// A date `days` from today, as a policy writes it.
fn days_from_today(days: i64) -> String {
    use pixi_policy::waivers::Date;
    Date::from_days(Date::today().days() + days).to_string()
}

#[test]
fn waivers_let_findings_through_with_their_reason_and_report_expired_and_unused_ones() {
    let dir = tempfile::tempdir().unwrap();
    let policy_file = dir.path().join("pixi-policy.toml");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi/02-flask/pixi.toml");
    let waiver = |package: &str, expires: &str| {
        format!(
            "\n[[waivers]]\nrule = \"licenses.deny\"\npackage = \"{package}\"\nreason = \"LEGAL-1234\"\nexpires = {expires}\n"
        )
    };
    let base = "[licenses]\ndeny = [\"GPL-3.0-only\"]\nunknown = \"allow\"\nambiguous = \"allow\"\n";
    let run = |format: &str| {
        let output = policy()
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--policy")
            .arg(&policy_file)
            .args(["--format", format])
            .output()
            .unwrap();
        (output.status.code(), String::from_utf8(output.stdout).unwrap())
    };

    // Both denied packages waived until next month: the check passes and says why.
    let soon = days_from_today(30);
    std::fs::write(
        &policy_file,
        format!(
            "{base}{}{}",
            waiver("readline", &soon),
            waiver("ld_impl_linux-64", &soon)
        ),
    )
    .unwrap();
    let (code, text) = run("text");
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("waived[licenses.deny] readline 8.3: ")
            && text.contains(&format!("; waiver: LEGAL-1234, expires {soon}")),
        "{text}"
    );
    assert!(
        text.ends_with("0 errors, 0 warnings, 6 waived in 206 packages across 4 environment-platform pairs\n"),
        "{text}"
    );
    let (_, json) = run("json");
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(doc["waived"][0]["waiver"]["reason"], "LEGAL-1234");
    let errors: Vec<String> = validator("schemas/pixi-policy-report.schema.json")
        .iter_errors(&doc)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    let (_, sarif) = run("sarif");
    let doc: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let suppressed = doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("suppressions").is_some())
        .count();
    assert_eq!(suppressed, 6);
    assert_eq!(
        doc["runs"][0]["results"][0]["suppressions"][0]["justification"],
        "LEGAL-1234"
    );

    // One expired, one for a package that is not there: the expired one fails again, both waivers are reported.
    std::fs::write(
        &policy_file,
        format!(
            "{base}{}{}{}",
            waiver("readline", &soon),
            waiver("ld_impl_linux-64", "2020-01-01"),
            waiver("not-here", &soon)
        ),
    )
    .unwrap();
    let (code, text) = run("text");
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("error[licenses.deny] ld_impl_linux-64 "), "{text}");
    assert!(text.contains("warning[waivers.expired] ld_impl_linux-64: waiver for licenses.deny on ld_impl_linux-64 expired on 2020-01-01"), "{text}");
    assert!(
        text.contains("warning[waivers.unused] not-here: waiver for licenses.deny on not-here matches no finding"),
        "{text}"
    );
    // The policy file as it was given (#121): here an absolute path in a temporary directory.
    assert!(text.contains(&format!("  --> {}:", policy_file.display())), "{text}");
}

/// #121: a finding about a waiver names the policy file the check read, relative to the working directory.
#[test]
fn a_waiver_finding_names_the_policy_file_given() {
    let ws = workspace(None);
    std::fs::create_dir(ws.path().join("policies")).unwrap();
    std::fs::write(
        ws.path().join("policies/strict.toml"),
        "max-waiver-days = 0\n\n[[waivers]]\nrule = \"bans.deny\"\npackage = \"nothing-here\"\nreason = \"r\"\nexpires = 2099-12-31\n",
    )
    .unwrap();
    let output = policy()
        .current_dir(ws.path())
        .args(["--policy", "policies/strict.toml"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("warning[waivers.unused] nothing-here: "), "{text}");
    assert!(text.contains("  --> policies/strict.toml:3\n"), "{text}");
    assert!(!text.contains("pixi-policy.toml"), "{text}");
}

#[test]
fn a_waiver_without_expires_exits_2() {
    let ws = workspace(Some(
        "[[waivers]]\nrule = \"licenses.deny\"\npackage = \"x\"\nreason = \"y\"\n",
    ));
    policy()
        .current_dir(ws.path())
        .assert()
        .code(2)
        .stderr(contains("expires"));
}

#[test]
fn manifest_findings_point_at_the_manifest_line() {
    let ws = workspace(Some("[manifest]\nrequired-platforms = [\"win-64\"]\n"));
    let failing = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifest/fail/pixi.toml");
    std::fs::copy(failing, ws.path().join("pixi.toml")).unwrap();
    let output = policy().current_dir(ws.path()).output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        text.contains("error[manifest.wildcard-spec] numpy: is given as \"*\" in [dependencies]\n  --> pixi.toml:8\n"),
        "{text}"
    );
    assert!(
        text.contains("error[manifest.python-pinned] python: ") && text.contains("  --> pixi.toml:7\n"),
        "{text}"
    );
    assert!(
        text.contains("error[manifest.required-platforms] platform win-64 is required"),
        "{text}"
    );

    let output = policy()
        .current_dir(ws.path())
        .args(["--format", "sarif"])
        .output()
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let numpy = doc["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "manifest.wildcard-spec" && r["properties"]["package"] == "numpy")
        .unwrap();
    let physical = &numpy["locations"][0]["physicalLocation"];
    assert_eq!(physical["artifactLocation"]["uri"], "pixi.toml");
    assert_eq!(physical["region"]["startLine"], 8);
}

#[test]
fn an_unreadable_manifest_exits_2_only_when_the_manifest_rules_need_it() {
    let ws = workspace(Some(""));
    std::fs::write(ws.path().join("pixi.toml"), "[workspace\n").unwrap();
    policy().current_dir(ws.path()).assert().code(0);
    std::fs::write(ws.path().join("pixi-policy.toml"), "[manifest]\n").unwrap();
    policy()
        .current_dir(ws.path())
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::manifest::read"));
}

/// #68's acceptance: on every example workspace, `init` writes a policy that `check` then passes.
#[test]
fn init_writes_a_policy_every_example_passes() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi");
    let out = tempfile::tempdir().unwrap();
    let mut seen = 0;
    for entry in std::fs::read_dir(&examples).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("pixi.toml");
        if !manifest.is_file() {
            continue;
        }
        seen += 1;
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let policy_file = out.path().join(format!("{name}.toml"));
        let init = policy()
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--policy")
            .arg(&policy_file)
            .arg("init")
            .output()
            .unwrap();
        assert_eq!(
            init.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        assert!(String::from_utf8_lossy(&init.stdout).starts_with("wrote "), "{name}");
        let check = policy()
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--policy")
            .arg(&policy_file)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&check.stdout);
        assert_eq!(
            check.status.code(),
            Some(0),
            "{name}: {text}\n{}",
            std::fs::read_to_string(&policy_file).unwrap()
        );
    }
    assert!(seen >= 19, "found {seen} example workspaces");
}

#[test]
fn init_never_overwrites_a_policy() {
    let ws = workspace(Some("[bans]\n"));
    policy()
        .current_dir(ws.path())
        .arg("init")
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::init::exists"));
    assert_eq!(
        std::fs::read_to_string(ws.path().join("pixi-policy.toml")).unwrap(),
        "[bans]\n"
    );
    let bare = workspace(None);
    policy()
        .current_dir(bare.path())
        .arg("init")
        .assert()
        .code(0)
        .stdout(contains("wrote "));
    policy().current_dir(bare.path()).assert().code(0);
    std::fs::remove_file(bare.path().join("pixi.lock")).unwrap();
    std::fs::remove_file(bare.path().join("pixi-policy.toml")).unwrap();
    policy()
        .current_dir(bare.path())
        .arg("init")
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::workspace::no_lockfile"));
}

#[test]
fn explain_says_what_a_rule_checks_and_lists_every_rule() {
    policy().args(["explain", "licenses.deny"]).assert().code(0).stdout(
        contains("licenses.deny: No package needs a license the policy denies").and(contains("[licenses]\ndeny = ")),
    );
    let list = policy().arg("explain").output().unwrap();
    let text = String::from_utf8(list.stdout).unwrap();
    assert_eq!(text.lines().count(), pixi_policy::explain::catalog().len());
    policy()
        .args(["explain", "licences.deny"])
        .assert()
        .code(2)
        .stderr(contains("pixi_policy::explain::unknown").and(contains("licenses.deny")));
}

#[test]
fn help_names_the_pixi_command() {
    policy()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(contains("Usage: pixi policy").and(contains("--policy <FILE>")));
}

#[test]
fn an_error_into_a_closed_pipe_still_exits_2() {
    // #70: the reader of standard error is gone before pixi-policy writes its report.
    let ws = workspace(Some(""));
    for _ in 0..5 {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("pixi-policy"))
            .current_dir(ws.path())
            .args(["--policy", "missing.toml"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stderr.take());
        assert_eq!(child.wait().unwrap().code(), Some(2));
    }
}

#[test]
fn version_details_needs_no_workspace_and_names_the_settings() {
    let dir = tempfile::tempdir().unwrap();
    let out = policy()
        .current_dir(dir.path())
        .arg("--version-details")
        .env("PIXI_POLICY_OSV_URL", "https://osv.mirror.example")
        .env("PIXI_EXE", dir.path().join("no-pixi-here"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.starts_with(&format!("pixi-policy {} (", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );
    assert!(text.contains("pixi:      not found\n"), "{text}");
    assert!(text.contains("offline:   yes (PIXI_POLICY_OFFLINE)\n"), "{text}");
    assert!(text.contains("(PIXI_POLICY_CACHE_DIR; "), "{text}");
    assert!(
        text.contains("overrides: PIXI_POLICY_OSV_URL=https://osv.mirror.example\n"),
        "{text}"
    );
    policy().arg("--build-info").assert().success();
}

#[test]
fn doctor_reports_offline_without_asking_and_fails_on_a_missing_lockfile() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lock");
    let dir = tempfile::tempdir().unwrap();
    let out = policy()
        .current_dir(fixtures.join("in-sync"))
        .args(["doctor", "--all"])
        .env("PIXI_EXE", dir.path().join("no-pixi-here"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.starts_with(&format!("pixi-policy {} (", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );
    assert!(text.contains("\nUpstreams (every one):\n  skipped   OSV "), "{text}");
    assert!(text.contains("  in sync   unknown: "), "{text}");
    assert!(text.ends_with("No problems found.\n"), "{text}");

    let out = policy()
        .current_dir(fixtures.join("missing-lockfile"))
        .arg("doctor")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .ends_with("1 problem: the workspace has no pixi.lock.\n")
    );
}
