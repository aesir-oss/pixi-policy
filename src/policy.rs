//! The policy file, `pixi-policy.toml`: a table per rule family, in the cargo-deny style. Unknown keys are errors, so
//! a misspelt section cannot quietly check nothing. Each family's table is filled in by its rules (#61 onward).

use std::path::Path;

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::Deserialize;
use thiserror::Error;

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
    pub licenses: Option<Table>,
    /// pixi.toml hygiene.
    #[serde(default)]
    pub manifest: Option<Table>,
    /// pixi.lock hygiene.
    #[serde(default)]
    pub lock: Option<Table>,
    /// Exceptions with a reason and an expiry date.
    #[serde(default)]
    pub waivers: Vec<Table>,
}

impl Policy {
    /// Parse a policy's text; `path` names it in a diagnostic.
    pub fn parse(text: &str, path: &str) -> Result<Self, PolicyError> {
        let policy: Self = Self::deserialize(text, path)?;
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
            "[sources]\nallowed-channels = [\"conda-forge\"]\nallow-git = false\n[[waivers]]\nrule = \"bans.deny\"\n",
            "p.toml",
        )
        .unwrap();
        let sources = policy.sources.unwrap();
        assert_eq!(sources.allowed_channels, Some(vec!["conda-forge".to_string()]));
        assert_eq!((sources.allow_git, sources.allow_url), (Some(false), None));
        assert_eq!(policy.waivers.len(), 1);
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
