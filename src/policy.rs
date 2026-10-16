//! The policy file, `pixi-policy.toml`: a table per rule family, in the cargo-deny style. Unknown keys are errors, so
//! a misspelt section cannot quietly check nothing. Each family's table is filled in by its rules (#61 onward).

use std::path::Path;

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde::Deserialize;
use thiserror::Error;
use toml::Spanned;

use crate::keys::{KEYS, Key, Merge};
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

    /// What a policy extends cannot be read or merged (#1).
    #[error("{path} {message}")]
    #[diagnostic(code(pixi_policy::policy::extends), help("{help}"))]
    Extends {
        path: String,
        message: String,
        help: String,
    },
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
    /// What a license name that could be more than one SPDX license gets (#7).
    #[serde(default)]
    pub ambiguous: Unknown,
}

/// What a known exploited advisory gets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// An error (the default: a KEV entry is a must-fix whatever its CVSS score).
    #[default]
    Error,
    Warn,
    Allow,
}

/// Which PyPI identities a conda package is looked up by (#3).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PypiMapping {
    /// The lockfile's PyPI purls, and conda-forge's mapping for a package the lockfile states none for.
    #[default]
    Prefix,
    /// The lockfile's PyPI purls only.
    Lock,
}

/// `[advisories]`: known vulnerabilities, from OSV with CISA's KEV catalog and FIRST's EPSS scores (#3). Every key
/// has a default once the table exists, so `[advisories]` alone fails on high and critical advisories and known
/// exploited ones.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Advisories {
    /// An advisory at or above this level fails (default high).
    pub fail_on: Option<crate::advisories::Level>,
    pub known_exploited: Option<Action>,
    /// An advisory whose EPSS score is at or above this probability fails; not set, EPSS is not asked.
    pub epss: Option<f64>,
    /// What an advisory with no severity gets (default warn).
    pub unknown: Option<Unknown>,
    pub pypi_mapping: Option<PypiMapping>,
    /// VEX documents whose statements take advisories out of the check: paths relative to the policy file, or
    /// pinned https URLs (#10).
    #[serde(default)]
    pub vex: Vec<String>,
}

impl Advisories {
    pub fn fail_on(&self) -> crate::advisories::Level {
        self.fail_on.unwrap_or(crate::advisories::Level::High)
    }

    pub fn known_exploited(&self) -> Action {
        self.known_exploited.unwrap_or_default()
    }

    pub fn unknown(&self) -> Unknown {
        self.unknown.unwrap_or_default()
    }

    pub fn pypi_mapping(&self) -> PypiMapping {
        self.pypi_mapping.unwrap_or_default()
    }

    fn check(&self) -> Result<(), String> {
        use crate::advisories::Level;
        if matches!(self.fail_on, Some(Level::Unknown | Level::None)) {
            return Err("fail-on takes \"low\", \"medium\", \"high\" or \"critical\"".into());
        }
        if self.epss.is_some_and(|epss| !(0.0..=1.0).contains(&epss)) {
            return Err("epss is a probability, from 0 to 1".into());
        }
        for location in &self.vex {
            if location.trim().is_empty() {
                return Err("a vex entry is empty: give a path or a URL".into());
            }
            if location.contains("://") && !(location.starts_with("https://") && crate::fetch::pinned(location)) {
                return Err(format!(
                    "vex {location:?} is not a pinned https URL: put a tag or commit in it, so it cannot change \
                     under you"
                ));
            }
        }
        Ok(())
    }
}

/// `[freshness]`: how old and how far behind a conda package may be, and whether its conda-forge feedstock may be
/// archived (#2). `archived` is on once the table exists; the limits are off until set.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Freshness {
    /// A build older than this many days fails.
    pub max_build_age_days: Option<u32>,
    /// A package more than this many major versions behind its channel's newest release fails.
    pub max_majors_behind: Option<u32>,
    /// A conda-forge package whose feedstock is archived fails (default true).
    pub archived: Option<bool>,
    /// What a package the data says nothing about gets (default warn).
    pub unknown: Option<Unknown>,
    /// PyPI packages are checked too, against pypi.org (default true, #52).
    pub pypi: Option<bool>,
}

impl Freshness {
    pub fn archived(&self) -> bool {
        self.archived.unwrap_or(true)
    }

    pub fn pypi(&self) -> bool {
        self.pypi.unwrap_or(true)
    }

    pub fn unknown(&self) -> Unknown {
        self.unknown.unwrap_or_default()
    }
}

/// `[hygiene]`: what an environment should not hold. `conda-pypi-duplicate` is on once the table exists (#11).
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Hygiene {
    /// A PyPI package a conda package in the same environment already provides (default true).
    pub conda_pypi_duplicate: Option<bool>,
}

impl Hygiene {
    pub fn conda_pypi_duplicate(&self) -> bool {
        self.conda_pypi_duplicate.unwrap_or(true)
    }
}

/// `[python]`: the Python minor version every environment runs (#42). Any patch release of `version` matches it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PythonRules {
    /// The standard, a minor version: `3.14`.
    pub version: String,
    /// What an environment whose Python is below the standard gets (default error).
    pub older: Option<Action>,
    /// What an environment whose Python is above the standard gets (default warn).
    pub newer: Option<Action>,
}

impl PythonRules {
    pub fn older(&self) -> Action {
        self.older.unwrap_or(Action::Error)
    }

    pub fn newer(&self) -> Action {
        self.newer.unwrap_or(Action::Warn)
    }

    /// The standard's major and minor version.
    pub fn standard(&self) -> Option<(u64, u64)> {
        let (major, minor) = self.version.trim().split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }
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
    /// Only this advisory, by its id or any alias (#3); `advisories.*` rules only.
    pub advisory: Option<String>,
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

/// `[policy]`: the policies this one builds on, and what a policy extending this one may loosen (#1). Read from the
/// file it is in only.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PolicyTable {
    /// The base policies, applied in order before this file.
    #[serde(default)]
    pub extends: Vec<Extends>,
    /// IDs of keys a policy extending this one may loosen (`licenses.allow`).
    #[serde(default)]
    pub overridable: Vec<String>,
}

/// One `[policy] extends` entry: a path relative to the file, a URL pinned to a tag or commit, or a URL with the
/// sha256 its content must have.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Extends {
    Location(String),
    Pinned(PinnedUrl),
}

/// `{ url = "...", sha256 = "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedUrl {
    pub url: String,
    pub sha256: String,
}

impl Extends {
    /// The path or URL.
    pub fn location(&self) -> &str {
        match self {
            Self::Location(location) => location,
            Self::Pinned(pinned) => &pinned.url,
        }
    }

    /// Whether it is a URL rather than a path.
    pub fn is_url(&self) -> bool {
        self.location().contains("://")
    }

    /// The sha256 the content must have, when the entry gives one.
    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Location(_) => None,
            Self::Pinned(pinned) => Some(&pinned.sha256),
        }
    }

    /// Why the entry cannot be used, if it cannot: a URL must be https and pinned, or carry a sha256.
    fn check(&self) -> Result<(), String> {
        let location = self.location();
        if location.trim().is_empty() {
            return Err("an entry is empty: give a path or a URL".into());
        }
        if let Some(sha256) = self.sha256() {
            if !self.is_url() {
                return Err(format!("{location:?}: a sha256 goes with a url, not a path"));
            }
            if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(format!("{location:?}: sha256 must be 64 lower-case hex digits"));
            }
            return Ok(());
        }
        if !self.is_url() {
            return Ok(());
        }
        if !location.starts_with("https://") {
            return Err(format!(
                "{location:?} is not https: give it with a sha256, {{ url = ..., sha256 = ... }}"
            ));
        }
        if !crate::fetch::pinned(location) {
            return Err(format!(
                "{location:?} is not pinned: put a tag or commit in the URL, or give it with a sha256, \
                 {{ url = ..., sha256 = ... }}, so the policy cannot change under you"
            ));
        }
        Ok(())
    }
}

/// The policy, as `pixi-policy.toml` writes it.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    /// What this policy extends, and what may loosen it.
    #[serde(default)]
    pub policy: Option<PolicyTable>,
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
    /// Known vulnerabilities.
    #[serde(default)]
    pub advisories: Option<Advisories>,
    /// How old and how far behind packages may be.
    #[serde(default)]
    pub freshness: Option<Freshness>,
    /// The Python minor version every environment runs.
    #[serde(default)]
    pub python: Option<PythonRules>,
    /// What an environment should not hold.
    #[serde(default)]
    pub hygiene: Option<Hygiene>,
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
        if let Some(table) = &policy.policy {
            for id in &table.overridable {
                overridable_key(id).map_err(|message| invalid(format!("[policy] overridable: {message}")))?;
            }
            for entry in &table.extends {
                entry
                    .check()
                    .map_err(|message| invalid(format!("[policy] extends: {message}")))?;
            }
        }
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
            if waiver.advisory.is_some() && !waiver.rule.starts_with("advisories.") {
                return Err(invalid(format!(
                    "the waiver on line {line} names an advisory, which only an advisories.* rule's waiver can"
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
        if let Some(advisories) = &policy.advisories {
            advisories
                .check()
                .map_err(|message| invalid(format!("[advisories]: {message}")))?;
        }
        if let Some(python) = &policy.python
            && python.standard().is_none()
        {
            return Err(invalid(format!(
                "[python]: version {:?} is not a minor version: write it as \"3.14\"",
                python.version
            )));
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

    /// Read the policy at `path`, with every policy it extends merged in (#1).
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        crate::extends::resolve(path).map(|resolved| resolved.policy)
    }

    /// Read the policy at `path` alone, ignoring what it extends; also its text.
    pub fn load_file(path: &Path) -> Result<(Self, String), PolicyError> {
        let shown = path.display().to_string();
        if !path.is_file() {
            return Err(PolicyError::Missing { path: shown });
        }
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: shown.clone(),
            source,
        })?;
        Ok((Self::parse(&text, &shown)?, text))
    }

    /// The policies this policy extends.
    pub fn extends(&self) -> &[Extends] {
        self.policy.as_ref().map_or(&[], |table| &table.extends)
    }

    /// The IDs of the keys a policy extending this one may loosen.
    pub fn overridable(&self) -> &[String] {
        self.policy.as_ref().map_or(&[], |table| &table.overridable)
    }
}

/// The key `id` names, when a policy may list it in `[policy] overridable`: one that may only narrow or be stricter.
pub fn overridable_key(id: &str) -> Result<&'static Key, String> {
    let key = KEYS.iter().find(|key| key.id() == id && !key.is_container());
    match key.map(|key| (key, key.merge)) {
        Some((key, Merge::Narrows | Merge::Stricter)) => Ok(key),
        Some((_, Merge::Grows)) => Err(format!(
            "{id:?} only adds up and is never loosened: lift one of its entries for a package with a [[waivers]] entry"
        )),
        Some(_) => Err(format!("{id:?} is not a key a policy can loosen")),
        None => {
            let ids: Vec<String> = KEYS
                .iter()
                .filter(|key| matches!(key.merge, Merge::Narrows | Merge::Stricter))
                .map(Key::id)
                .collect();
            Err(format!(
                "{id:?} is not a policy key (the keys that can be loosened are {})",
                ids.join(", ")
            ))
        }
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
    fn advisories_take_a_level_a_probability_and_waivers_an_advisory() {
        let advisories = Policy::parse("[advisories]\n", "p.toml").unwrap().advisories.unwrap();
        assert_eq!(advisories.fail_on(), crate::advisories::Level::High);
        assert_eq!(advisories.known_exploited(), Action::Error);
        assert_eq!(
            (advisories.unknown(), advisories.pypi_mapping()),
            (Unknown::Warn, PypiMapping::Prefix)
        );
        for (bad, wanted) in [
            ("[advisories]\nfail-on = \"none\"\n", "fail-on takes"),
            ("[advisories]\nepss = 1.5\n", "a probability"),
            (
                "[[waivers]]\nrule = \"bans.deny\"\npackage = \"x\"\nadvisory = \"CVE-1\"\nreason = \"r\"\nexpires = 2027-01-01\n",
                "only an advisories.* rule's waiver",
            ),
        ] {
            let err = Policy::parse(bad, "p.toml").unwrap_err().to_string();
            assert!(err.contains(wanted), "{bad}: {err}");
        }
    }

    #[test]
    fn python_takes_a_minor_version() {
        let python = Policy::parse("[python]\nversion = \"3.14\"\n", "p.toml")
            .unwrap()
            .python
            .unwrap();
        assert_eq!(
            (python.standard(), python.older(), python.newer()),
            (Some((3, 14)), Action::Error, Action::Warn)
        );
        for bad in ["3", "3.14.2", "3.x", ""] {
            let err = Policy::parse(&format!("[python]\nversion = {bad:?}\n"), "p.toml")
                .unwrap_err()
                .to_string();
            assert!(err.contains("is not a minor version"), "{bad}: {err}");
        }
        assert!(
            Policy::parse("[python]\nnewer = \"error\"\n", "p.toml").is_err(),
            "version is required"
        );
    }

    #[test]
    fn an_extends_url_must_be_pinned() {
        let parse = |entry: &str| Policy::parse(&format!("[policy]\nextends = [{entry}]\n"), "p.toml");
        let sha = "0".repeat(64);
        for ok in [
            "\"../base.toml\"".to_string(),
            "\"https://github.com/acme/policies/raw/v3/base.toml\"".to_string(),
            format!("{{ url = \"http://intranet/base.toml\", sha256 = \"{sha}\" }}"),
        ] {
            parse(&ok).unwrap_or_else(|err| panic!("{ok}: {err}"));
        }
        for (bad, wanted) in [
            (
                "\"https://github.com/acme/policies/raw/main/base.toml\"".to_string(),
                "is not pinned",
            ),
            ("\"http://intranet/v3/base.toml\"".to_string(), "is not https"),
            (
                format!("{{ url = \"https://x/base.toml\", sha256 = \"{}\" }}", "A".repeat(64)),
                "64 lower-case hex",
            ),
            (
                format!("{{ url = \"base.toml\", sha256 = \"{sha}\" }}"),
                "goes with a url",
            ),
            ("\" \"".to_string(), "empty"),
        ] {
            let err = parse(&bad).unwrap_err().to_string();
            assert!(err.contains(wanted), "{bad}: {err}");
        }
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
