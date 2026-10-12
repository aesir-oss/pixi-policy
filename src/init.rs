//! `pixi policy init` (#68): a starting policy the workspace passes today, from its pixi.lock and manifest. The
//! channels and indexes in use become the allowed ones, the licenses seen become `allow`, and the hygiene rules are
//! on except where the manifest would fail them, which the policy says in a comment. It never overwrites a file.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::io::Write as _;
use std::path::Path;

use crate::license::{self, License};
use crate::license_policy::Lists;
use crate::lockfile::{self, Kind};
use miette::Diagnostic;
use rattler_lock::LockFile;
use thiserror::Error;

use crate::check::CheckError;
use crate::manifest::{DependencyKind, Manifest};
use crate::rules::manifest::python_pinned;
use crate::rules::sources::{Origin, channel_allowed, origin};

/// Why `init` wrote nothing.
#[derive(Debug, Error, Diagnostic)]
pub enum InitError {
    #[error("{path} already exists; pixi policy init never overwrites a policy")]
    #[diagnostic(
        code(pixi_policy::init::exists),
        help("check it with `pixi policy`, or move it aside to start again")
    )]
    Exists { path: String },

    #[error("cannot write {path}: {message}")]
    #[diagnostic(code(pixi_policy::init::write))]
    Write { path: String, message: String },
}

/// What the workspace uses today, across every environment and platform.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InUse {
    pub channels: BTreeSet<String>,
    pub indexes: BTreeSet<String>,
    pub git: bool,
    pub url: bool,
    pub path: bool,
    /// SPDX licensees the shared verdict accepts, one per identifier seen.
    pub licenses: BTreeSet<String>,
}

/// A channel as the policy would write it: its name when the name alone matches it, its URL otherwise.
fn channel_entry(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let name = trimmed
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map(|(_, path)| path);
    match name {
        Some(name) if channel_allowed(url, &[name.to_string()]) => name.to_string(),
        _ => trimmed.to_string(),
    }
}

/// The licensees in one SPDX expression that the shared verdict accepts.
fn licensees(expression: &str) -> Vec<String> {
    let mode = spdx::ParseMode {
        allow_deprecated: true,
        ..spdx::ParseMode::STRICT
    };
    let Ok(parsed) = spdx::Expression::parse_mode(expression, mode) else {
        return Vec::new();
    };
    parsed
        .requirements()
        .map(|req| req.req.to_string())
        .filter(|licensee| Lists::new(std::slice::from_ref(licensee), &[]).is_ok())
        .collect()
}

/// What the workspace uses, read from every environment and platform of `lock`.
pub fn in_use(lock: &LockFile) -> Result<InUse, CheckError> {
    let mut used = InUse::default();
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment)? {
            for fact in lockfile::read(lock, &environment, Some(&platform))?.packages {
                match origin(&fact) {
                    Origin::Channel(url) => drop(used.channels.insert(channel_entry(&url))),
                    Origin::Index(url) => drop(used.indexes.insert(url.trim_end_matches('/').to_string())),
                    Origin::Git(_) => used.git = true,
                    Origin::Url(_) => used.url = true,
                    Origin::Path(_) => used.path = true,
                }
                if fact.kind != Kind::Pypi
                    && let Some(License::Expression(expression)) = fact.license.as_deref().map(license::normalize)
                {
                    used.licenses.extend(licensees(&expression));
                }
            }
        }
    }
    Ok(used)
}

/// `1 channel`, `2 channels`.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn quoted(text: &str) -> String {
    toml::Value::String(text.to_string()).to_string()
}

fn list(items: impl IntoIterator<Item = String>) -> String {
    let items: Vec<String> = items.into_iter().map(|item| quoted(&item)).collect();
    if items.len() <= 3 {
        return format!("[{}]", items.join(", "));
    }
    format!(
        "[\n{}]",
        items.iter().map(|item| format!("  {item},\n")).collect::<String>()
    )
}

/// The policy text for a workspace that uses `used` and has `manifest`.
pub fn propose(used: &InUse, manifest: &Manifest) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# pixi-policy.toml, written by `pixi policy init` from what this workspace uses today."
    );
    let _ = writeln!(
        out,
        "# Tighten it from here; `pixi policy explain <RULE>` says what each rule checks.\n"
    );
    let _ = writeln!(out, "[sources]");
    let _ = writeln!(out, "allowed-channels = {}", list(used.channels.iter().cloned()));
    if !used.indexes.is_empty() {
        let _ = writeln!(out, "allowed-indexes = {}", list(used.indexes.iter().cloned()));
    }
    for (key, seen) in [
        ("allow-git", used.git),
        ("allow-url", used.url),
        ("allow-path", used.path),
    ] {
        let note = if seen { "  # in use today" } else { "" };
        let _ = writeln!(out, "{key} = {seen}{note}");
    }
    let _ = writeln!(
        out,
        "\n[bans]\ndeny = []  # e.g. {{ name = \"pycrypto\", reason = \"unmaintained\", use-instead = \"pycryptodome\" }}"
    );
    let _ = writeln!(out, "\n[licenses]");
    let _ = writeln!(
        out,
        "# Every license the conda packages declare today. pixi.lock records no PyPI licenses."
    );
    let _ = writeln!(out, "allow = {}", list(used.licenses.iter().cloned()));
    let _ = writeln!(out, "unknown = \"warn\"");
    let _ = writeln!(out, "\n[manifest]");
    let wildcards = manifest
        .dependencies
        .iter()
        .filter(|dep| dep.spec.as_deref().map(str::trim) == Some("*"))
        .count();
    if wildcards > 0 {
        let _ = writeln!(
            out,
            "wildcard-spec = false  # {} \"*\" today; give them ranges, then remove this",
            plural(wildcards, "dependency is", "dependencies are")
        );
    }
    let unpinned = manifest.dependencies.iter().any(|dep| {
        dep.kind == DependencyKind::Conda
            && dep.name.eq_ignore_ascii_case("python")
            && !dep.spec.as_deref().is_some_and(python_pinned)
    });
    if unpinned {
        let _ = writeln!(
            out,
            "python-pinned = false  # python is not pinned to one minor version today"
        );
    }
    if let Some((platforms, _)) = &manifest.platforms {
        let _ = writeln!(out, "required-platforms = {}", list(platforms.iter().cloned()));
    }
    let _ = writeln!(out, "\n[lock]  # present, complete and in-sync are all on");
    out
}

/// Write `text` to `path`, unless something is there already.
pub fn write(path: &Path, text: &str) -> Result<(), InitError> {
    let shown = path.display().to_string();
    let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Err(InitError::Exists { path: shown }),
        Err(err) => {
            return Err(InitError::Write {
                path: shown,
                message: err.to_string(),
            });
        }
    };
    file.write_all(text.as_bytes()).map_err(|err| InitError::Write {
        path: shown,
        message: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources_fixture() -> (LockFile, Manifest) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources");
        (
            crate::check::load_lockfile(&dir.join("pixi.lock")).unwrap(),
            Manifest::load(&dir.join("pixi.toml")).unwrap(),
        )
    }

    #[test]
    fn what_is_in_use_is_read_from_every_package() {
        let (lock, _) = sources_fixture();
        let used = in_use(&lock).unwrap();
        assert_eq!(
            used.channels.iter().map(String::as_str).collect::<Vec<_>>(),
            ["bioconda", "conda-forge", "https://conda.acme.internal/prod"],
            "names where the name matches, prefix.dev and anaconda.org spellings of conda-forge as one"
        );
        assert_eq!(used.indexes.len(), 3);
        assert!(used.git && used.url && used.path);
        assert!(used.licenses.contains("Zlib"), "{:?}", used.licenses);
    }

    #[test]
    fn licensees_split_an_expression_and_keep_exceptions() {
        assert_eq!(licensees("MIT OR Apache-2.0"), ["MIT", "Apache-2.0"]);
        assert_eq!(
            licensees("GPL-3.0-only WITH GCC-exception-3.1"),
            ["GPL-3.0-only WITH GCC-exception-3.1"]
        );
        assert!(licensees("not ( valid").is_empty());
    }

    #[test]
    fn the_proposal_is_a_valid_policy_the_fixture_passes() {
        let (lock, manifest) = sources_fixture();
        let text = propose(&in_use(&lock).unwrap(), &manifest);
        let policy = crate::policy::Policy::parse(&text, "p.toml").unwrap();
        let outcome = crate::check::run(&lock, &policy, &crate::check::rules()).unwrap();
        assert!(!outcome.failed(), "{:?}\n{text}", outcome.findings);
        assert!(text.contains("allow-git = true  # in use today"), "{text}");
        assert!(text.contains("required-platforms = [\"linux-64\"]"), "{text}");
    }

    #[test]
    fn hygiene_rules_the_manifest_fails_today_are_off_with_a_reason() {
        let manifest = Manifest::parse(
            "[workspace]\nplatforms = [\"linux-64\"]\n[dependencies]\npython = \">=3.10\"\nnumpy = \"*\"\n",
            false,
        )
        .unwrap();
        let text = propose(&InUse::default(), &manifest);
        assert!(
            text.contains("wildcard-spec = false  # 1 dependency is \"*\" today"),
            "{text}"
        );
        assert!(text.contains("python-pinned = false"), "{text}");
        assert!(!text.contains("allowed-indexes"), "{text}");
        let many = list((0..5).map(|i| format!("x{i}")));
        assert!(many.starts_with("[\n  \"x0\",\n"), "{many}");
    }

    #[test]
    fn init_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi-policy.toml");
        write(&path, "[sources]\n").unwrap();
        assert!(matches!(write(&path, "other"), Err(InitError::Exists { .. })));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[sources]\n");
        assert!(matches!(
            write(&dir.path().join("no/such/dir.toml"), "x"),
            Err(InitError::Write { .. })
        ));
    }
}
