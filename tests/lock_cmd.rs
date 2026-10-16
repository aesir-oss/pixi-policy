//! `pixi policy lock` (#54) end to end, with a fake pixi (a shell script, so Unix only; the logic's unit tests run
//! everywhere): its `lock` writes the python fixture's pixi.lock, its `install` leaves a mark.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python")
}

/// A workspace whose pixi.lock says "old" until the fake pixi locks it, with `policy`; and the fake pixi.
fn setup(policy: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixture().join("pixi.toml"), dir.path().join("pixi.toml")).unwrap();
    std::fs::write(dir.path().join("pixi.lock"), "old").unwrap();
    std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    let pixi = dir.path().join("fake-pixi");
    std::fs::write(
        &pixi,
        format!(
            "#!/bin/sh\necho \"$@\" >> \"{log}\"\ncase \"$1\" in\n  lock) cp \"{lock}\" \"{ws}/pixi.lock\" ;;\n  install) \
             touch \"{ws}/installed\" ;;\nesac\n",
            log = dir.path().join("calls").display(),
            lock = fixture().join("pixi.lock").display(),
            ws = dir.path().display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&pixi, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, pixi)
}

fn lock(dir: &Path, pixi: &Path, args: &[&str]) -> (Option<i32>, String) {
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("PIXI_EXE", pixi)
        .current_dir(dir)
        .arg("lock")
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn a_passing_lock_is_kept_and_installed_when_asked() {
    let (dir, pixi) = setup("[python]\nversion = \"3.13\"\nolder = \"allow\"\nnewer = \"allow\"\n");
    let (code, out) = lock(dir.path(), &pixi, &["--install", "--", "--no-install"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(
        std::fs::read_to_string(dir.path().join("pixi.lock"))
            .unwrap()
            .starts_with("version:")
    );
    assert!(dir.path().join("installed").exists());
    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
    assert!(calls.starts_with("lock --manifest-path ") && calls.lines().next().unwrap().ends_with(" --no-install"));
    assert!(calls.lines().nth(1).unwrap().starts_with("install --frozen"), "{calls}");
}

#[test]
fn a_failing_lock_is_kept_or_restored_and_never_installed() {
    let policy = "[python]\nversion = \"3.13\"\n";
    let (dir, pixi) = setup(policy);
    let (code, out) = lock(dir.path(), &pixi, &["--install"]);
    assert_eq!(code, Some(1));
    assert!(out.contains("error[python.older]"), "{out}");
    assert!(
        std::fs::read_to_string(dir.path().join("pixi.lock"))
            .unwrap()
            .starts_with("version:")
    );
    assert!(!dir.path().join("installed").exists());

    let (dir, pixi) = setup(policy);
    let (code, _) = lock(dir.path(), &pixi, &["--restore"]);
    assert_eq!(code, Some(1));
    assert_eq!(std::fs::read_to_string(dir.path().join("pixi.lock")).unwrap(), "old");
}
