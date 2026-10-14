//! `[policy] extends` (#1), run as a user would: a workspace policy built on a shared base, what loosening the base
//! does, and `pixi policy show`. Diagnostics are matched by code, since miette wraps their text.

use std::path::Path;

use assert_cmd::Command;

const BASE: &str = "[policy]\noverridable = [\"licenses.allow\"]\n\n[sources]\nallow-git = false\n\n[bans]\n\
                    deny = [{ name = \"django\", version = \"<6\", reason = \"too old\" }]\n";

/// A workspace (01-django) with `policies/base.toml` and the given `pixi-policy.toml` beside its pixi.toml.
fn workspace(policy: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi/01-django");
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(example.join(file), dir.path().join(file)).unwrap();
    }
    std::fs::create_dir(dir.path().join("policies")).unwrap();
    std::fs::write(dir.path().join("policies/base.toml"), BASE).unwrap();
    std::fs::write(dir.path().join("pixi-policy.toml"), policy).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::cargo_bin("pixi-policy")
        .unwrap()
        .env("NO_COLOR", "1")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn a_ban_from_the_base_fails_the_workspace_with_its_own_bans_too() {
    let ws = workspace(
        "[policy]\nextends = [\"policies/base.toml\"]\n\n[bans]\ndeny = [{ name = \"djangorestframework\", version = \"<3.15\" }]\n",
    );
    let (code, out, err) = run(ws.path(), &[]);
    assert_eq!(code, Some(1), "{out}{err}");
    assert!(
        out.contains("error[bans.deny] django ") && out.contains("is banned (version <6): too old"),
        "{out}"
    );
    assert!(out.contains("error[bans.deny] djangorestframework "), "{out}");
}

#[test]
fn loosening_what_the_base_does_not_allow_exits_2() {
    let ws = workspace("[policy]\nextends = [\"policies/base.toml\"]\n\n[sources]\nallow-git = true\n");
    let (code, out, err) = run(ws.path(), &[]);
    assert_eq!(code, Some(2), "{out}{err}");
    assert!(err.contains("pixi_policy::policy::extends"), "{err}");
    assert!(out.is_empty(), "{out}");
    // What the base lists in overridable may be loosened.
    let ws = workspace("[policy]\nextends = [\"policies/base.toml\"]\n\n[licenses]\nallow = [\"MIT\"]\n");
    std::fs::write(
        ws.path().join("policies/base.toml"),
        format!("{BASE}\n[licenses]\nallow = [\"BSD-3-Clause\"]\n"),
    )
    .unwrap();
    let (code, out, err) = run(ws.path(), &["show", "--resolved"]);
    assert_eq!(code, Some(0), "{out}{err}");
    let base = format!("policies{}base.toml", std::path::MAIN_SEPARATOR);
    assert!(
        out.contains(&format!(
            "allow = [\"MIT\"]  # pixi-policy.toml, loosens {base} (overridable there)\n"
        )),
        "{out}"
    );
}

#[test]
fn show_prints_the_policy_as_written_or_resolved() {
    let local = "[policy]\nextends = [\"policies/base.toml\"]\n\n[bans]\ndeny = [{ name = \"pycrypto\" }]\n";
    let ws = workspace(local);
    let (code, out, _) = run(ws.path(), &["show"]);
    assert_eq!((code, out.as_str()), (Some(0), local));
    let (code, out, err) = run(ws.path(), &["show", "--resolved"]);
    assert_eq!(code, Some(0), "{err}");
    let separator = std::path::MAIN_SEPARATOR;
    let base = format!("policies{separator}base.toml");
    assert!(
        out.contains(&format!("# Read in order: {base}, pixi-policy.toml\n")),
        "{out}"
    );
    assert!(out.contains(&format!("allow-git = false  # {base}\n")), "{out}");
    assert!(
        out.contains("  { name = \"pycrypto\" },  # pixi-policy.toml\n"),
        "{out}"
    );
}

#[test]
fn a_policy_that_extends_itself_exits_2() {
    let ws = workspace("[policy]\nextends = [\"policies/base.toml\"]\n");
    std::fs::write(
        ws.path().join("policies/base.toml"),
        format!(
            "[policy]\nextends = [\"../pixi-policy.toml\"]\n\n{}",
            &BASE[BASE.find("[sources]").unwrap()..]
        ),
    )
    .unwrap();
    let (code, out, err) = run(ws.path(), &["show", "--resolved"]);
    assert_eq!(code, Some(2), "{out}{err}");
    assert!(
        err.contains("pixi_policy::policy::extends") && err.contains("extends itself"),
        "{err}"
    );
}
