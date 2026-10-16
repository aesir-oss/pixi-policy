//! `pixi policy init` (#68): a starting policy the workspace passes today, from its pixi.lock and manifest. The
//! channels and indexes in use become the allowed ones, the licenses seen become `allow`, and the hygiene rules are
//! on except where the manifest would fail them, which the policy says in a comment. Since #53 it also proposes
//! `[python]` from the Python the environments resolve, `[hygiene]`, the workspace's own `exclude-newer` cooldown, and
//! `[advisories]` and `[freshness]` commented out, since they use the network. It never overwrites a file.

use std::collections::{BTreeMap, BTreeSet};
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
    /// The Python minors the environments resolve, each with the environments on it.
    pub pythons: BTreeMap<(u64, u64), BTreeSet<String>>,
    /// PyPI packages a conda package in the same environment provides, by pixi.lock's own purls.
    pub duplicates: usize,
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
pub fn in_use(lock: &LockFile, wheels: Option<&crate::wheel::Data>) -> Result<InUse, CheckError> {
    let mut used = InUse::default();
    let hygiene = crate::policy::Policy::parse("[hygiene]\n", "init").expect("a fixed policy parses");
    let duplicates = crate::rules::hygiene::rules(None);
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment)? {
            let facts = lockfile::read(lock, &environment, Some(&platform))?;
            used.duplicates += duplicates
                .iter()
                .map(|rule| rule.check(&hygiene, &facts).len())
                .sum::<usize>();
            for fact in facts.packages {
                if matches!(fact.kind, Kind::CondaBinary | Kind::CondaSource)
                    && fact.name == "python"
                    && let Some(minor) = fact.version.as_deref().and_then(crate::rules::python::minor)
                {
                    used.pythons.entry(minor).or_default().insert(environment.clone());
                }
                match origin(&fact) {
                    Origin::Channel(url) => drop(used.channels.insert(channel_entry(&url))),
                    Origin::Index(url) => drop(used.indexes.insert(url.trim_end_matches('/').to_string())),
                    Origin::Git(_) => used.git = true,
                    Origin::Url(_) => used.url = true,
                    Origin::Path(_) => used.path = true,
                }
                let declared = match fact.kind {
                    Kind::Pypi => match wheels.and_then(|data| data.for_package(&fact)) {
                        Some(crate::wheel::Answer::Declared(raw)) => Some(raw.clone()),
                        _ => None,
                    },
                    _ => fact.license.clone(),
                };
                if let Some(License::Expression(expression)) = declared.as_deref().map(license::normalize) {
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
        "# Every license the packages declare today: pixi.lock's, and the PyPI wheels' METADATA it could read."
    );
    let _ = writeln!(out, "allow = {}", list(used.licenses.iter().cloned()));
    let _ = writeln!(out, "unknown = \"warn\"");
    let _ = writeln!(
        out,
        "\n# Known vulnerabilities and freshness use the network; turn them on when it is there.\n\
         # [advisories]  # fails on high and critical advisories and known exploited ones\n\
         # [freshness]\n# max-build-age-days = 730\n# max-majors-behind = 1"
    );
    match used.duplicates {
        0 => {
            let _ = writeln!(out, "\n[hygiene]  # no PyPI package duplicates a conda package today");
        }
        n => {
            let _ = writeln!(
                out,
                "\n[hygiene]\nconda-pypi-duplicate = false  # {} today; remove them, then this",
                plural(
                    n,
                    "PyPI package duplicates a conda one",
                    "PyPI packages duplicate conda ones"
                )
            );
        }
    }
    if let Some((&(major, minor), _)) = used.pythons.iter().next_back() {
        let _ = writeln!(out, "\n[python]\nversion = \"{major}.{minor}\"");
        let behind: Vec<String> = used
            .pythons
            .iter()
            .filter(|(version, _)| **version != (major, minor))
            .map(|((ma, mi), envs)| format!("{} on {ma}.{mi}", envs.iter().cloned().collect::<Vec<_>>().join(", ")))
            .collect();
        if !behind.is_empty() {
            let _ = writeln!(out, "older = \"warn\"  # {} today", behind.join("; "));
        }
    }
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
    let cooldown = manifest
        .exclude_newer
        .workspace
        .as_ref()
        .and_then(|(value, _)| crate::rules::manifest::duration(value))
        .map(|seconds| (seconds / 86_400.0).floor() as u32)
        .filter(|days| *days >= 1);
    match cooldown {
        Some(days) => {
            let _ = writeln!(
                out,
                "min-exclude-newer-days = {days}  # the workspace's exclude-newer today"
            );
        }
        None => {
            let _ = writeln!(
                out,
                "# min-exclude-newer-days = 7  # with exclude-newer = \"7d\" in the workspace, a cooldown for new releases"
            );
        }
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
        let used = in_use(&lock, None).unwrap();
        assert_eq!(
            used.channels.iter().map(String::as_str).collect::<Vec<_>>(),
            ["bioconda", "conda-forge", "https://conda.acme.internal/prod"],
            "names where the name matches, prefix.dev and anaconda.org spellings of conda-forge as one"
        );
        assert_eq!(used.indexes.len(), 3);
        assert!(used.git && used.url && used.path);
        assert!(used.licenses.contains("Zlib"), "{:?}", used.licenses);
        let python = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python/pixi.lock");
        let used = in_use(&crate::check::load_lockfile(&python).unwrap(), None).unwrap();
        assert_eq!(
            used.pythons.keys().copied().collect::<Vec<_>>(),
            [(3, 12), (3, 13), (3, 14)]
        );
        assert_eq!(used.pythons[&(3, 12)].iter().collect::<Vec<_>>(), ["old"]);
        let hygiene = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hygiene/pixi.lock");
        assert_eq!(
            in_use(&crate::check::load_lockfile(&hygiene).unwrap(), None)
                .unwrap()
                .duplicates,
            1,
            "msgpack, by its purl"
        );
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
        let text = propose(&in_use(&lock, None).unwrap(), &manifest);
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
    fn the_newer_tables_are_proposed_so_the_workspace_passes() {
        let mut used = InUse::default();
        used.pythons.insert((3, 14), ["default".to_string()].into());
        used.pythons
            .insert((3, 12), ["legacy".to_string(), "old".to_string()].into());
        used.duplicates = 2;
        let manifest = Manifest::parse("[workspace]\nplatforms = []\nexclude-newer = \"14d\"\n", false).unwrap();
        let text = propose(&used, &manifest);
        assert!(
            text.contains("\n[python]\nversion = \"3.14\"\nolder = \"warn\"  # legacy, old on 3.12 today\n"),
            "{text}"
        );
        assert!(
            text.contains("conda-pypi-duplicate = false  # 2 PyPI packages duplicate conda ones today"),
            "{text}"
        );
        assert!(
            text.contains("min-exclude-newer-days = 14  # the workspace's exclude-newer today"),
            "{text}"
        );
        assert!(
            text.contains("# [advisories]") && text.contains("# [freshness]"),
            "{text}"
        );
        let policy = crate::policy::Policy::parse(&text, "p.toml").unwrap();
        assert_eq!(policy.python.unwrap().older(), crate::policy::Action::Warn);

        let plain = propose(&InUse::default(), &Manifest::parse("[workspace]\n", false).unwrap());
        assert!(!plain.contains("\n[python]"), "no Python, no [python]: {plain}");
        assert!(plain.contains("[hygiene]  # no PyPI package duplicates"), "{plain}");
        assert!(plain.contains("# min-exclude-newer-days = 7"), "{plain}");
        let dated = Manifest::parse("[workspace]\nexclude-newer = \"2026-01-01\"\n", false).unwrap();
        assert!(
            propose(&InUse::default(), &dated).contains("# min-exclude-newer-days = 7"),
            "a date is not a duration"
        );
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
