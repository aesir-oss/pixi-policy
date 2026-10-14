//! The pre-commit hook in `pre-commit-mirror/` (#5): which files start it, what the release workflow renders into the
//! mirror repository, and that CI tries it. CI's `pre-commit-hook` job runs `pre-commit-mirror/try.sh` against the
//! wheel on PyPI; these tests need no network.

use std::path::PathBuf;

use predicates::prelude::*;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(crate_dir().join(path)).unwrap()
}

/// The value of `key:` in the hook definition.
fn hook_value(key: &str) -> String {
    let hooks = read("pre-commit-mirror/.pre-commit-hooks.yaml");
    let prefix = format!("  {key}: ");
    hooks
        .lines()
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .or_else(|| line.strip_prefix(&format!("- {key}: ")))
        })
        .unwrap_or_else(|| panic!("no {key} in the hook: {hooks}"))
        .to_string()
}

#[test]
fn the_hook_runs_the_wheel_binary_once_per_commit() {
    assert_eq!(hook_value("id"), "pixi-policy");
    assert_eq!(hook_value("entry"), "pixi-policy");
    assert_eq!(hook_value("language"), "python");
    // The binary finds the workspace itself; file names on the command line would be read as a subcommand.
    assert_eq!(hook_value("pass_filenames"), "false");
}

#[test]
fn the_hook_runs_when_a_file_the_check_reads_changes() {
    let files = predicate::str::is_match(hook_value("files")).unwrap();
    for path in [
        "pixi.toml",
        "pixi.lock",
        "pyproject.toml",
        "pixi-policy.toml",
        "app/pixi.toml",
        "services/api/pixi.lock",
    ] {
        assert!(files.eval(path), "the hook skips {path}");
    }
    for path in [
        "README.md",
        "mypixi.toml",
        "pixi.toml.bak",
        "pixi.lock/notes.txt",
        "docs/pixi-policy.md",
    ] {
        assert!(!files.eval(path), "the hook runs on {path}");
    }
}

#[test]
fn the_mirror_pins_the_wheel_of_its_own_version() {
    let pyproject = read("pre-commit-mirror/pyproject.toml.in");
    assert!(pyproject.contains(r#"version = "@VERSION@""#), "{pyproject}");
    assert!(
        pyproject.contains(r#"dependencies = ["pixi-policy==@VERSION@"]"#),
        "{pyproject}"
    );
    let readme = read("pre-commit-mirror/README.md.in");
    assert!(readme.contains("rev: v@VERSION@"), "{readme}");
    // The README's link lands on the docs section.
    assert!(readme.contains("/latest/ci/#a-pre-commit-hook"), "{readme}");
    assert!(read("docs/ci.md").contains("\n## A pre-commit hook\n"));
}

#[test]
fn the_release_job_renders_and_tags_the_mirror_after_pypi() {
    let workflow = read(".github/workflows/release-artifacts.yml");
    let job = workflow
        .split("\n  pre-commit-mirror:\n")
        .nth(1)
        .expect("release-artifacts.yml has no pre-commit-mirror job");
    let job = job.split("\n\n  #").next().unwrap();
    for needle in [
        "needs: [tag, pypi]",
        "if: needs.tag.outputs.prerelease == 'false'",
        "repositories: pixi-policy-pre-commit",
        r#"../source/pre-commit-mirror/render.sh "${TAG#v}" ."#,
        r#"git tag "${TAG}""#,
    ] {
        assert!(
            job.contains(needle),
            "the pre-commit-mirror job lacks `{needle}`:\n{job}"
        );
    }
}

#[test]
fn ci_tries_the_hook() {
    let ci = read(".github/workflows/ci.yml");
    assert!(ci.contains("pre-commit-mirror/try.sh"), "{ci}");
    assert!(ci.contains("needs: [lint, test, coverage, deny, msrv, build, docs, action, pre-commit-hook]"));
}

#[cfg(unix)]
#[test]
fn render_fills_in_the_version() {
    let dest = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("bash")
        .arg(crate_dir().join("pre-commit-mirror/render.sh"))
        .arg("9.8.7")
        .arg(dest.path())
        .status()
        .unwrap();
    assert!(status.success());
    let rendered = |name: &str| std::fs::read_to_string(dest.path().join(name)).unwrap();
    assert_eq!(
        rendered(".pre-commit-hooks.yaml"),
        read("pre-commit-mirror/.pre-commit-hooks.yaml")
    );
    let pyproject = rendered("pyproject.toml");
    assert!(
        pyproject.contains(r#"dependencies = ["pixi-policy==9.8.7"]"#),
        "{pyproject}"
    );
    assert!(rendered("README.md").contains("rev: v9.8.7"));
    for name in ["pyproject.toml", "README.md"] {
        assert!(!rendered(name).contains("@VERSION@"), "{name} keeps a placeholder");
    }
    let mut names: Vec<String> = std::fs::read_dir(dest.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [".pre-commit-hooks.yaml", "README.md", "pyproject.toml"]);
}
