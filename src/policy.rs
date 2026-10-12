//! The policy file, `pixi-policy.toml`: a table per rule family, in the cargo-deny style. Unknown keys are errors, so
//! a misspelt section cannot quietly check nothing. Each family's table is filled in by its rules (#61 onward).

use std::path::Path;

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::Deserialize;
use thiserror::Error;
use toml::Spanned;

use crate::waivers::Date;

/// Why the policy could not be read.
#[derive(Debug, Error, Diagnostic)]
pub enum PolicyError {
    #[error("no policy: {path} does not exist")]
    #[diagnostic(
        code(pixi_policy::policy::missing),
        help(
            "write the policy in pixi-policy.toml beside pixi.toml (an empty file checks nothing), or pass --policy \
             <file>; a check without a policy would pass every workspace"
        )
    )]
    Missing { path: String },

    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_policy::policy::read))]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    #[diagnostic(transparent)]
    Parse(Box<ParseError>),

    #[error("{path}: {message}")]
    #[diagnostic(
        code(pixi_policy::policy::invalid),
        help("fix the entry in the policy; see the docs for what each key takes")
    )]
    Invalid { path: String, message: String },
}

/// A policy file that is not valid TOML or has keys pixi-policy does not know, pointing at the spot.
#[derive(Debug, Error, Diagnostic)]
#[error("{path} is not a valid policy: {message}")]
#[diagnostic(
    code(pixi_policy::policy::parse),
    help("the policy is a table per rule family; see `pixi policy --help` and the docs for the keys each takes")
)]
pub struct ParseError {
    pub path: String,
    pub message: String,
    #[source_code]
    pub src: NamedSource<String>,
    #[label("here")]
    pub span: Option<SourceSpan>,
}

/// A rule family's settings, as written. Each family reads its own keys from it as its rules are added.
pub type Table = toml::Table;

/// `[sources]`: where packages may come from. A key left out restricts nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Sources {
    /// Channels conda packages may come from: a name (`conda-forge`, matching its anaconda.org and prefix.dev URLs)
    /// or a full URL.
    pub allowed_channels: Option<Vec<String>>,
    /// Indexes PyPI packages may come from, by URL.
    pub allowed_indexes: Option<Vec<String>>,
    /// Whether packages may come from a git repository.
    pub allow_git: Option<bool>,
    /// Whether packages may come from a direct URL (an archive, not a channel or an index).
    pub allow_url: Option<bool>,
    /// Whether packages may come from a local path.
    pub allow_path: Option<bool>,
}

/// Which kind of package a ban applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageKind {
    Conda,
    Pypi,
}

/// One `[bans] deny` entry: a package, optionally only some of its versions, that is never allowed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Ban {
    pub name: String,
    /// A version range: conda's syntax for conda packages, PEP 440 for PyPI ones (`<3`, `>=1.0,<1.1.1w`).
    pub version: Option<String>,
    /// A conda build-string pattern (`*_cuda*`); conda packages only.
    pub build: Option<String>,
    /// Only conda packages, or only PyPI ones (and the conda packages that provide them).
    pub kind: Option<PackageKind>,
    pub reason: Option<String>,
    pub use_instead: Option<String>,
}

/// `[bans]`: packages and versions that are never allowed.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Bans {
    #[serde(default)]
    pub deny: Vec<Ban>,
}

/// What a package with no license, or one that is not an SPDX expression, gets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unknown {
    /// A warning (the default, decided on #63: pixi.lock records no PyPI licenses).
    #[default]
    Warn,
    /// An error.
    Error,
    /// Nothing.
    Allow,
}

/// `[licenses]`: allow, review and deny lists of SPDX licenses. Entries are SPDX identifiers or patterns with `*`
/// (`LGPL-*`), expanded against the SPDX license list.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Licenses {
    /// When given, only these (and `review`) are acceptable.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Acceptable after a review: a warning.
    #[serde(default)]
    pub review: Vec<String>,
    /// Never acceptable.
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub unknown: Unknown,
}

/// One `[[waivers]]` entry: an exception for one rule and one package, with a reason and an expiry date.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Waiver {
    /// The rule it waives (`licenses.deny`).
    pub rule: String,
    pub package: String,
    /// Only this version, environment or platform, when given.
    pub version: Option<String>,
    pub environment: Option<String>,
    pub platform: Option<String>,
    pub reason: String,
    /// The last day it applies; required (#66).
    pub expires: toml::value::Datetime,
    /// Its line in the policy file, filled in by [`Policy::parse`].
    #[serde(skip)]
    pub line: Option<u32>,
}

impl Waiver {
    /// The expiry as a date; [`Policy::parse`] has checked that it is one.
    pub fn expires_on(&self) -> Date {
        Date::from_toml(&self.expires).expect("Policy::parse rejects an expires that is not a date")
    }
}

/// `[manifest]`: pixi.toml hygiene. `wildcard-spec` and `python-pinned` are on once the table exists (decided on #64).
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ManifestRules {
    /// No dependency given as `*` (default true).
    pub wildcard_spec: Option<bool>,
    /// Python pinned to one minor version or narrower (default true).
    pub python_pinned: Option<bool>,
    /// Platforms the workspace must list.
    pub required_platforms: Option<Vec<String>>,
}

/// `[lock]`: pixi.lock hygiene. Every rule is on once the table exists, like `[manifest]` (#64, #65).
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct LockRules {
    /// The workspace has a pixi.lock (default true).
    pub present: Option<bool>,
    /// Every environment is locked for every platform (default true).
    pub complete: Option<bool>,
    /// pixi.lock still satisfies the manifest, as `pixi list --locked` judges it (default true).
    pub in_sync: Option<bool>,
}

/// The policy, as `pixi-policy.toml` writes it.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    /// Where packages may come from.
    #[serde(default)]
    pub sources: Option<Sources>,
    /// Packages and versions that are never allowed.
    #[serde(default)]
    pub bans: Option<Bans>,
    /// Allow, review and deny lists of SPDX licenses.
    #[serde(default)]
    pub licenses: Option<Licenses>,
    /// pixi.toml hygiene.
    #[serde(default)]
    pub manifest: Option<ManifestRules>,
    /// pixi.lock hygiene.
    #[serde(default)]
    pub lock: Option<LockRules>,
    /// A waiver's `expires` further than this many days after today is reported (`waivers.too-long`); 0 turns that
    /// off. Default 365 (decided on #66).
    #[serde(default)]
    pub max_waiver_days: Option<u32>,
    /// Exceptions with a reason and an expiry date.
    #[serde(default)]
    pub waivers: Vec<Spanned<Waiver>>,
}

impl Policy {
    /// Parse a policy's text; `path` names it in a diagnostic.
    pub fn parse(text: &str, path: &str) -> Result<Self, PolicyError> {
        let mut policy: Self = Self::deserialize(text, path)?;
        let invalid = |message: String| PolicyError::Invalid {
            path: path.to_string(),
            message,
        };
        let known: Vec<&'static str> = crate::check::rules().iter().map(|rule| rule.id()).collect();
        for waiver in &mut policy.waivers {
            let line = text[..waiver.span().start].matches('\n').count() + 1;
            let waiver = waiver.get_mut();
            waiver.line = u32::try_from(line).ok();
            if !known.contains(&waiver.rule.as_str()) {
                return Err(invalid(format!(
                    "the waiver on line {line} names rule {:?}, which pixi-policy does not have (it has {})",
                    waiver.rule,
                    known.join(", ")
                )));
            }
            if Date::from_toml(&waiver.expires).is_none() {
                return Err(invalid(format!(
                    "the waiver on line {line} expires {}, which is not a date: write it as YYYY-MM-DD",
                    waiver.expires
                )));
            }
        }
        if let Some(licenses) = &policy.licenses {
            crate::rules::licenses::Compiled::new(licenses).map_err(|message| PolicyError::Invalid {
                path: path.to_string(),
                message: format!("[licenses]: {message}"),
            })?;
        }
        if let Some(bans) = &policy.bans {
            for ban in &bans.deny {
                crate::rules::bans::Matcher::new(ban).map_err(|message| PolicyError::Invalid {
                    path: path.to_string(),
                    message: format!("[bans] deny entry for {:?}: {message}", ban.name),
                })?;
            }
        }
        Ok(policy)
    }

    fn deserialize(text: &str, path: &str) -> Result<Self, PolicyError> {
        toml::from_str(text).map_err(|err| {
            PolicyError::Parse(Box::new(ParseError {
                path: path.to_string(),
                message: err.message().to_string(),
                span: err.span().map(SourceSpan::from),
                src: NamedSource::new(path, text.to_string()),
            }))
        })
    }

    /// Read the policy at `path`.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let shown = path.display().to_string();
        if !path.is_file() {
            return Err(PolicyError::Missing { path: shown });
        }
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: shown.clone(),
            source,
        })?;
        Self::parse(&text, &shown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_policy_is_valid_and_each_family_is_a_table() {
        assert_eq!(Policy::parse("", "p.toml").unwrap(), Policy::default());
        let policy = Policy::parse(
            "[sources]\nallowed-channels = [\"conda-forge\"]\nallow-git = false\n",
            "p.toml",
        )
        .unwrap();
        let sources = policy.sources.unwrap();
        assert_eq!(sources.allowed_channels, Some(vec!["conda-forge".to_string()]));
        assert_eq!((sources.allow_git, sources.allow_url), (Some(false), None));
        assert!(policy.waivers.is_empty());
    }

    #[test]
    fn an_unknown_key_is_an_error_that_points_at_it() {
        let err = Policy::parse("[sources]\n[nope]\nx = 1\n", "p.toml").unwrap_err();
        let PolicyError::Parse(parse) = &err else {
            panic!("{err:?}")
        };
        assert!(parse.message.contains("nope"), "{}", parse.message);
        assert!(parse.span.is_some());
        assert!(err.to_string().starts_with("p.toml is not a valid policy"));
    }

    #[test]
    fn a_misspelt_sources_key_is_an_error() {
        let err = Policy::parse("[sources]\nallowed-channel = []\n", "p.toml").unwrap_err();
        assert!(err.to_string().contains("allowed-channel"), "{err}");
    }

    #[test]
    fn a_missing_policy_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Policy::load(&dir.path().join("pixi-policy.toml")),
            Err(PolicyError::Missing { .. })
        ));
    }
}
