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

/// The policy, as `pixi-policy.toml` writes it.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    /// Where packages may come from.
    #[serde(default)]
    pub sources: Option<Table>,
    /// Packages and versions that are never allowed.
    #[serde(default)]
    pub bans: Option<Table>,
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
            "[sources]\nallowed-channels = [\"conda-forge\"]\n[[waivers]]\nrule = \"bans.deny\"\n",
            "p.toml",
        )
        .unwrap();
        assert!(policy.sources.unwrap().contains_key("allowed-channels"));
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
    fn a_missing_policy_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Policy::load(&dir.path().join("pixi-policy.toml")),
            Err(PolicyError::Missing { .. })
        ));
    }
}
