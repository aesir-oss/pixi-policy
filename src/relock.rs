//! `pixi policy lock` (#54): run `pixi lock`, check the pixi.lock it writes, and with `--install` run `pixi install`
//! once the check passes. A failing check leaves the new pixi.lock in place unless `--restore` asks for the one from
//! before (decided on #54). It is a convenience, not a gate: `pixi install`, `pixi run` and `pixi add` re-lock a
//! workspace without it, so the pre-commit hook and the Action stay what enforces the policy.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use miette::{IntoDiagnostic, WrapErr};

use crate::workspace::Workspace;

/// What `pixi policy lock` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Put the pixi.lock from before back when the check fails.
    pub restore: bool,
    /// Run `pixi install --frozen` when the check passes.
    pub install: bool,
    /// Passed on to `pixi lock`.
    pub pixi_args: Vec<String>,
}

/// How pixi is run: its arguments in, its exit code out (`None` when it was killed by a signal).
pub type Pixi<'a> = &'a dyn Fn(&[OsString]) -> std::io::Result<Option<i32>>;

/// Run the pixi pixi-policy was started from (`PIXI_EXE`), or the one on PATH, with the terminal it has.
pub fn pixi(args: &[OsString]) -> std::io::Result<Option<i32>> {
    let program = std::env::var_os("PIXI_EXE").unwrap_or_else(|| "pixi".into());
    Command::new(program).args(args).status().map(|status| status.code())
}

fn pixi_failed(what: &str, code: Option<i32>) -> miette::Report {
    let code = code.map_or("a signal".to_string(), |code| format!("exit code {code}"));
    miette::miette!(
        code = "pixi_policy::lock::pixi",
        help = "fix what pixi reported above; pixi policy lock runs pixi with the arguments given after --",
        "`pixi {what}` failed ({code})"
    )
}

/// Lock, check with `check` (which prints its report and gives its exit code), and restore or install as `options`
/// ask; the exit code is the check's, or `pixi install`'s when it ran.
pub fn run(
    workspace: &Workspace,
    options: &Options,
    pixi: Pixi<'_>,
    check: impl FnOnce() -> miette::Result<i32>,
) -> miette::Result<i32> {
    let before = std::fs::read(&workspace.lockfile).ok();
    let manifest: OsString = workspace.manifest.clone().into();
    let mut lock: Vec<OsString> = vec!["lock".into(), "--manifest-path".into(), manifest.clone()];
    lock.extend(options.pixi_args.iter().map(OsString::from));
    match pixi(&lock)
        .into_diagnostic()
        .wrap_err("cannot run pixi: run pixi-policy as `pixi policy`, or with pixi on PATH (or PIXI_EXE set)")?
    {
        Some(0) => {}
        code => return Err(pixi_failed("lock", code)),
    }
    let code = check()?;
    if code != crate::EXIT_OK {
        if options.restore {
            restore(&workspace.lockfile, before.as_deref())?;
            let _ = writeln!(
                std::io::stderr(),
                "pixi policy lock: the check failed, so {} is back as it was",
                workspace.lockfile.display()
            );
        }
        return Ok(code);
    }
    if options.install {
        let install = vec!["install".into(), "--frozen".into(), "--manifest-path".into(), manifest];
        match pixi(&install).into_diagnostic().wrap_err("cannot run pixi")? {
            Some(0) => {}
            code => return Err(pixi_failed("install --frozen", code)),
        }
    }
    Ok(code)
}

/// Put `lockfile` back to `before`, or remove it when there was none.
fn restore(lockfile: &Path, before: Option<&[u8]>) -> miette::Result<()> {
    let done = match before {
        Some(bytes) => std::fs::write(lockfile, bytes),
        None => std::fs::remove_file(lockfile),
    };
    done.into_diagnostic()
        .wrap_err_with(|| format!("cannot restore {}", lockfile.display()))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn workspace(dir: &Path, lock: Option<&str>) -> Workspace {
        std::fs::write(dir.join("pixi.toml"), "[workspace]\n").unwrap();
        if let Some(text) = lock {
            std::fs::write(dir.join("pixi.lock"), text).unwrap();
        }
        Workspace::find(Some(&dir.join("pixi.toml")), dir).unwrap()
    }

    /// A pixi that writes `new` as pixi.lock on `lock`, answers `codes` in turn, and records what it was asked.
    fn fake<'a>(
        dir: &'a Path,
        new: &'a str,
        codes: &'a RefCell<Vec<Option<i32>>>,
        calls: &'a RefCell<Vec<String>>,
    ) -> impl Fn(&[OsString]) -> std::io::Result<Option<i32>> + 'a {
        move |args: &[OsString]| {
            let words: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
            if words[0] == "lock" {
                std::fs::write(dir.join("pixi.lock"), new).unwrap();
            }
            calls.borrow_mut().push(words.join(" "));
            Ok(codes.borrow_mut().remove(0))
        }
    }

    #[test]
    fn a_failing_check_keeps_the_new_lock_unless_asked_to_restore() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Some("old"));
        let calls = RefCell::new(Vec::new());
        let codes = RefCell::new(vec![Some(0)]);
        let pixi = fake(dir.path(), "new", &codes, &calls);
        let options = Options {
            pixi_args: vec!["--no-install".into()],
            ..Options::default()
        };
        assert_eq!(run(&ws, &options, &pixi, || Ok(1)).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&ws.lockfile).unwrap(), "new");
        assert!(calls.borrow()[0].starts_with("lock --manifest-path ") && calls.borrow()[0].ends_with(" --no-install"));

        codes.borrow_mut().push(Some(0));
        std::fs::write(&ws.lockfile, "old").unwrap();
        let restore = Options {
            restore: true,
            install: true,
            ..Options::default()
        };
        assert_eq!(run(&ws, &restore, &pixi, || Ok(1)).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&ws.lockfile).unwrap(), "old");
        assert_eq!(calls.borrow().len(), 2, "no install after a failing check");

        let fresh = tempfile::tempdir().unwrap();
        let ws = workspace(fresh.path(), None);
        codes.borrow_mut().push(Some(0));
        let pixi = fake(fresh.path(), "new", &codes, &calls);
        run(&ws, &restore, &pixi, || Ok(1)).unwrap();
        assert!(!ws.lockfile.exists(), "a lockfile that did not exist before is removed");
    }

    #[test]
    fn a_passing_check_installs_when_asked_and_pixis_failures_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ws = workspace(dir.path(), Some("old"));
        let calls = RefCell::new(Vec::new());
        let codes = RefCell::new(vec![Some(0), Some(0)]);
        let pixi = fake(dir.path(), "new", &codes, &calls);
        let install = Options {
            install: true,
            ..Options::default()
        };
        assert_eq!(run(&ws, &install, &pixi, || Ok(0)).unwrap(), 0);
        assert!(calls.borrow()[1].starts_with("install --frozen --manifest-path "));

        codes.borrow_mut().push(Some(3));
        let err = run(&ws, &install, &pixi, || Ok(0)).unwrap_err().to_string();
        assert_eq!(err, "`pixi lock` failed (exit code 3)");

        codes.borrow_mut().extend([Some(0), None]);
        let err = run(&ws, &install, &pixi, || Ok(0)).unwrap_err().to_string();
        assert_eq!(err, "`pixi install --frozen` failed (a signal)");

        let missing = |_: &[OsString]| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        let err = run(&ws, &install, &missing, || Ok(0)).unwrap_err();
        assert!(format!("{err:?}").contains("PIXI_EXE"), "{err:?}");
    }
}
