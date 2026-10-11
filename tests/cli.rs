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
            .stdout(contains("0 errors, 0 warnings in ").and(contains(" across ")));
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
            stdout.starts_with("0 errors, 0 warnings in ") && !stdout.contains(" in 0 packages"),
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

#[test]
fn help_names_the_pixi_command() {
    policy()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(contains("Usage: pixi policy").and(contains("--policy <FILE>")));
}
