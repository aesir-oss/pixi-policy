//! Running the policy's rules over every environment and platform of the lockfile.
//!
//! A rule is a pure function of the policy and one environment's facts (`common::lockfile`), returning findings: the
//! same answer on every machine. Rule IDs are `family.rule` (`bans.deny`, `sources.channels`).

use std::fmt;

use common::lockfile::{self, Facts, ReadError};
use miette::Diagnostic;
use rattler_lock::LockFile;
use thiserror::Error;

use crate::policy::Policy;

/// Why the lockfile could not be read.
#[derive(Debug, Error, Diagnostic)]
pub enum CheckError {
    #[error("cannot read the lockfile {path}: {message}")]
    #[diagnostic(
        code(pixi_policy::lockfile::parse),
        help(
            "run `pixi lock` to rewrite an old or damaged pixi.lock, or upgrade pixi-policy if it is newer than it reads"
        )
    )]
    Parse { path: String, message: String },

    #[error("{0}")]
    #[diagnostic(code(pixi_policy::lockfile::read))]
    Read(String),
}

impl From<ReadError> for CheckError {
    fn from(err: ReadError) -> Self {
        CheckError::Read(err.to_string())
    }
}

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Fails the check.
    Error,
    /// Reported, does not fail the check.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        })
    }
}

/// The workspace file a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum File {
    Lockfile,
    Manifest,
    /// The policy itself: a finding about a waiver.
    Policy,
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            File::Lockfile => "pixi.lock",
            File::Manifest => "pixi.toml",
            File::Policy => "pixi-policy.toml",
        })
    }
}

/// One thing a rule found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `family.rule`.
    pub rule: &'static str,
    pub severity: Severity,
    pub package: Option<String>,
    pub version: Option<String>,
    pub environment: String,
    pub platform: String,
    /// Where it is: the file, and the line when the rule knows it.
    pub file: File,
    pub line: Option<u32>,
    pub message: String,
    /// What to do about it.
    pub help: Option<String>,
}

/// A finding a waiver let through, and the waiver's reason and expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waived {
    pub finding: Finding,
    pub reason: String,
    /// `YYYY-MM-DD`.
    pub expires: String,
}

/// A rule of the policy.
pub trait Rule {
    /// `family.rule`.
    fn id(&self) -> &'static str;
    /// What the rule checks, in one line (SARIF's rule description, the docs' rule list).
    fn summary(&self) -> &'static str;
    /// What this rule finds in one environment and platform's packages.
    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding>;
}

/// Every rule pixi-policy has.
pub fn rules() -> Vec<Box<dyn Rule>> {
    crate::rules::all()
}

/// What a check found, and what it looked at.
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    /// Findings a waiver let through: reported, never failing the check.
    pub waived: Vec<Waived>,
    /// Environment and platform pairs checked.
    pub targets: usize,
    /// Packages across all of them.
    pub packages: usize,
}

impl Outcome {
    /// Whether any finding fails the check.
    pub fn failed(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Error)
    }
}

/// Check every environment and platform of `lock` against `policy` with `rules`.
pub fn run(lock: &LockFile, policy: &Policy, rules: &[Box<dyn Rule>]) -> Result<Outcome, CheckError> {
    let mut outcome = Outcome::default();
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment)? {
            let facts = lockfile::read(lock, &environment, Some(&platform))?;
            outcome.targets += 1;
            outcome.packages += facts.packages.len();
            for rule in rules {
                outcome.findings.extend(rule.check(policy, &facts));
            }
        }
    }
    outcome.findings.sort_by(|a, b| {
        (a.severity, a.rule, &a.package, &a.environment, &a.platform).cmp(&(
            b.severity,
            b.rule,
            &b.package,
            &b.environment,
            &b.platform,
        ))
    });
    Ok(outcome)
}

/// Read the lockfile at `path`.
pub fn load_lockfile(path: &std::path::Path) -> Result<LockFile, CheckError> {
    LockFile::from_path(path).map_err(|err| CheckError::Parse {
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule that finds every package named `python`, for the framework's tests.
    struct NoPython;

    impl Rule for NoPython {
        fn id(&self) -> &'static str {
            "test.no-python"
        }
        fn summary(&self) -> &'static str {
            "no python"
        }
        fn check(&self, _policy: &Policy, facts: &Facts) -> Vec<Finding> {
            facts
                .packages
                .iter()
                .filter(|p| p.name == "python")
                .map(|p| Finding {
                    rule: self.id(),
                    severity: Severity::Error,
                    package: Some(p.name.clone()),
                    version: p.version.clone(),
                    environment: facts.environment.clone(),
                    platform: facts.platform.clone(),
                    file: File::Lockfile,
                    line: None,
                    message: "found".into(),
                    help: None,
                })
                .collect()
        }
    }

    fn fixture() -> LockFile {
        load_lockfile(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pixi-sbom/tests/fixtures/with-pypi/pixi.lock"),
        )
        .unwrap()
    }

    #[test]
    fn every_environment_and_platform_is_checked_by_every_rule() {
        let lock = fixture();
        let none = run(&lock, &Policy::default(), &rules()).unwrap();
        assert!(none.targets > 1 && none.packages > 0);
        assert!(none.findings.is_empty() && !none.failed());

        let rules: Vec<Box<dyn Rule>> = vec![Box::new(NoPython)];
        let some = run(&lock, &Policy::default(), &rules).unwrap();
        assert!(some.failed());
        assert!(some.findings.iter().all(|f| f.rule == "test.no-python"));
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(NoPython.summary(), "no python");
        assert_eq!(
            (File::Lockfile.to_string(), File::Manifest.to_string()),
            ("pixi.lock".into(), "pixi.toml".into())
        );
    }

    #[test]
    fn an_unreadable_lockfile_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi.lock");
        std::fs::write(&path, "not a lockfile").unwrap();
        assert!(matches!(load_lockfile(&path), Err(CheckError::Parse { .. })));
        let err: CheckError = ReadError::UnknownCurrentPlatform.into();
        assert_eq!(err.to_string(), "cannot determine the current platform");
    }
}
