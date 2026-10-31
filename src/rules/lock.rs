//! `lock.*`: pixi.lock hygiene (#65). Every rule is on once `[lock]` exists, and each can be set to false.
//!
//! - `lock.present`: the workspace has a pixi.lock. Without `[lock]`, a missing lockfile stays an input error (exit 2).
//! - `lock.complete`: every environment the manifest defines is locked for every platform it is solved for.
//! - `lock.in-sync`: pixi.lock still satisfies the manifest, as pixi itself judges it: `pixi list --locked` with
//!   `PIXI_OFFLINE=1`, a satisfiability check with no solve, no network and no writes (decided on #65). When pixi
//!   cannot be run, the rule reports that it could not check, as a warning, rather than passing.

use std::path::Path;
use std::process::{Command, Output};

use crate::lockfile;
use rattler_lock::LockFile;

use crate::check::{File, Finding, Rule, Severity};
use crate::manifest::Manifest;
use crate::policy::Policy;
use crate::workspace::Workspace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Present,
    Complete,
    InSync,
}

struct LockRule {
    which: Which,
}

/// The three `lock.*` rules, for the rule list; [`check`] runs them.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [Which::Present, Which::Complete, Which::InSync]
        .into_iter()
        .map(|which| Box::new(LockRule { which }) as Box<dyn Rule>)
        .collect()
}

impl Rule for LockRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::Present => "lock.present",
            Which::Complete => "lock.complete",
            Which::InSync => "lock.in-sync",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::Present => "The workspace has a pixi.lock",
            Which::Complete => "Every environment is locked for every platform it is solved for",
            Which::InSync => "pixi.lock still satisfies the manifest",
        }
    }
}

/// How `lock.in-sync` asks pixi: the manifest and a platform in pixi.lock, and pixi's answer.
pub type Pixi<'a> = &'a dyn Fn(&Path, &str) -> std::io::Result<Output>;

/// Run `pixi list --locked` offline for `manifest` on `platform` (the pixi pixi-policy was started from, or the one on
/// PATH).
pub fn run_pixi(manifest: &Path, platform: &str) -> std::io::Result<Output> {
    let pixi = std::env::var_os("PIXI_EXE").unwrap_or_else(|| "pixi".into());
    Command::new(pixi)
        .args(["list", "--locked", "--platform", platform, "--manifest-path"])
        .arg(manifest)
        .env("PIXI_OFFLINE", "1")
        .output()
}

fn finding(
    rule: &'static str,
    severity: Severity,
    environment: &str,
    platform: &str,
    message: String,
    help: &str,
) -> Finding {
    Finding {
        rule,
        severity,
        package: None,
        version: None,
        environment: environment.into(),
        platform: platform.into(),
        file: File::Lockfile,
        line: None,
        message,
        help: Some(help.into()),
        advisory: Vec::new(),
    }
}

/// What the `lock.*` rules find: `lock` is `None` when the workspace has no pixi.lock.
pub fn check(
    policy: &Policy,
    workspace: &Workspace,
    manifest: &Manifest,
    lock: Option<&LockFile>,
    pixi: Pixi<'_>,
) -> Vec<Finding> {
    let Some(settings) = &policy.lock else {
        return Vec::new();
    };
    let on = |setting: Option<bool>| setting.unwrap_or(true);
    let mut findings = Vec::new();
    let Some(lock) = lock else {
        if on(settings.present) {
            findings.push(finding(
                "lock.present",
                Severity::Error,
                "",
                "",
                "the workspace has no pixi.lock".into(),
                "run `pixi lock` and commit pixi.lock, so every install resolves to the same packages",
            ));
        }
        return findings;
    };
    if on(settings.complete) {
        let locked = lockfile::environment_names(lock);
        for (environment, platforms) in manifest.environment_platforms() {
            if !locked.contains(&environment) {
                findings.push(finding(
                    "lock.complete",
                    Severity::Error,
                    &environment,
                    "",
                    format!("environment {environment} is not in pixi.lock"),
                    "run `pixi lock` to lock every environment",
                ));
                continue;
            }
            let locked_platforms = lockfile::platform_names(lock, &environment).unwrap_or_default();
            for platform in platforms.iter().filter(|p| !locked_platforms.contains(p)) {
                findings.push(finding(
                    "lock.complete",
                    Severity::Error,
                    &environment,
                    platform,
                    format!("environment {environment} is not locked for {platform}"),
                    "run `pixi lock` to lock every platform the workspace lists",
                ));
            }
        }
    }
    if on(settings.in_sync) {
        let platform = lockfile::environment_names(lock).iter().find_map(|env| {
            lockfile::platform_names(lock, env)
                .ok()
                .and_then(|p| p.into_iter().next())
        });
        let answer = match platform {
            Some(platform) => pixi(&workspace.manifest, &platform),
            None => Ok(Output {
                status: exit_status(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        };
        match answer {
            Ok(output) if output.status.success() => {}
            Ok(output) if String::from_utf8_lossy(&output.stderr).contains("not up-to-date") => findings.push(finding(
                "lock.in-sync",
                Severity::Error,
                "",
                "",
                "pixi.lock does not satisfy the manifest any more (pixi list --locked)".into(),
                "run `pixi lock` and commit the result",
            )),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let why = stderr
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("no message")
                    .to_string();
                findings.push(could_not_check(&why));
            }
            Err(err) => findings.push(could_not_check(&format!("pixi could not be run: {err}"))),
        }
    }
    findings
}

fn could_not_check(why: &str) -> Finding {
    finding(
        "lock.in-sync",
        Severity::Warning,
        "",
        "",
        format!("could not check whether pixi.lock satisfies the manifest: {why}"),
        "run pixi-policy as `pixi policy`, or with pixi on PATH (or PIXI_EXE set), so it can ask pixi",
    )
}

/// An exit status with `code`, for an answer pixi did not have to give.
#[cfg(unix)]
pub(crate) fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code << 8)
}

/// An exit status with `code`, for an answer pixi did not have to give.
#[cfg(windows)]
pub(crate) fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (Workspace, Manifest, Option<LockFile>) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lock")
            .join(name);
        let workspace = Workspace::find(Some(&dir.join("pixi.toml")), &dir).unwrap();
        let manifest = Manifest::load(&workspace.manifest).unwrap();
        let lock = workspace
            .has_lockfile()
            .then(|| crate::check::load_lockfile(&workspace.lockfile).unwrap());
        (workspace, manifest, lock)
    }

    fn found(policy: &str, name: &str, pixi: Pixi<'_>) -> Vec<(&'static str, Severity, String, String)> {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        let (workspace, manifest, lock) = fixture(name);
        check(&policy, &workspace, &manifest, lock.as_ref(), pixi)
            .into_iter()
            .map(|f| (f.rule, f.severity, f.environment, f.platform))
            .collect()
    }

    /// pixi's real answer.
    fn real(manifest: &Path, platform: &str) -> std::io::Result<Output> {
        run_pixi(manifest, platform)
    }

    fn missing(_: &Path, _: &str) -> std::io::Result<Output> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
    }

    const ALL: &str = "[lock]\n";

    #[test]
    fn an_in_sync_lockfile_passes_every_rule() {
        assert!(found(ALL, "in-sync", &real).is_empty());
    }

    #[test]
    fn a_missing_lockfile_is_lock_present_and_nothing_else() {
        assert_eq!(
            found(ALL, "missing-lockfile", &real),
            [("lock.present", Severity::Error, String::new(), String::new())]
        );
        assert!(found("[lock]\npresent = false\n", "missing-lockfile", &real).is_empty());
    }

    #[test]
    fn a_missing_environment_and_a_missing_platform_are_lock_complete() {
        let env = found("[lock]\nin-sync = false\n", "missing-environment", &real);
        assert_eq!(
            env,
            [("lock.complete", Severity::Error, "docs".to_string(), String::new())]
        );
        let platform = found("[lock]\nin-sync = false\n", "missing-platform", &real);
        assert_eq!(
            platform,
            [(
                "lock.complete",
                Severity::Error,
                "default".to_string(),
                "win-64".to_string()
            )]
        );
    }

    #[test]
    fn a_stale_lock_is_lock_in_sync_as_pixi_judges_it() {
        assert_eq!(
            found(ALL, "stale", &real),
            [("lock.in-sync", Severity::Error, String::new(), String::new())]
        );
        // A missing environment or platform is also out of sync.
        let both: Vec<&str> = found(ALL, "missing-platform", &real).into_iter().map(|f| f.0).collect();
        assert_eq!(both, ["lock.complete", "lock.in-sync"]);
        assert!(found("[lock]\ncomplete = false\nin-sync = false\n", "stale", &real).is_empty());
    }

    #[test]
    fn when_pixi_cannot_answer_in_sync_is_a_warning_not_a_pass() {
        let got = found(ALL, "in-sync", &missing);
        assert_eq!(got, [("lock.in-sync", Severity::Warning, String::new(), String::new())]);
        let failing = |_: &Path, _: &str| {
            Ok(Output {
                status: exit_status(1),
                stdout: Vec::new(),
                stderr: b"\n  Error: something else\n".to_vec(),
            })
        };
        let policy = Policy::parse(ALL, "p.toml").unwrap();
        let (workspace, manifest, lock) = fixture("in-sync");
        let findings = check(&policy, &workspace, &manifest, lock.as_ref(), &failing);
        assert_eq!(
            findings[0].message,
            "could not check whether pixi.lock satisfies the manifest: Error: something else"
        );
        assert!(found("", "in-sync", &missing).is_empty(), "no [lock], no findings");
        assert!(rules().iter().all(|r| !r.summary().is_empty()));
        assert!(Policy::parse("[lock]\nfresh = true\n", "p.toml").is_err());
    }
}
