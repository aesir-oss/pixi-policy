//! `bans.deny`: packages and versions that are never allowed (#62).
//!
//! A ban names a package and, optionally, a version range and a conda build-string pattern. Conda versions and builds
//! are compared by rattler (`1.1.1w`, `*_cuda*`), PyPI versions by PEP 440. A ban without `kind`, or with
//! `kind = "pypi"`, also matches a conda package whose pixi.lock purls say it provides that PyPI package (conda
//! `pytorch` for PyPI `torch`), compared with PEP 440 against the provided version (decided on #62).

use std::str::FromStr;

use crate::lockfile::{Fact, Facts, Kind};
use crate::purl::normalize_pypi_name;
use pep440_rs::{Version as PypiVersion, VersionSpecifiers};
use rattler_conda_types::{ParseStrictness, StringMatcher, Version as CondaVersion, VersionSpec};

use crate::check::{File, Finding, Rule, Severity};
use crate::policy::{Ban, PackageKind, Policy};

/// A parser's error as one clause for the policy diagnostic (#122): its first line, without a trailing colon or a
/// "Failed to parse version:" lead-in. pep440's errors go on to draw the input and carets on lines of their own.
fn reason(err: &impl std::fmt::Display) -> String {
    let text = err.to_string();
    let first = text.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or("");
    let first = first
        .strip_prefix("Failed to parse version:")
        .map_or(first, str::trim_start);
    first.trim_end_matches(':').trim_end().to_string()
}

/// A ban, compiled.
#[derive(Debug)]
pub struct Matcher<'a> {
    ban: &'a Ban,
    conda: Option<VersionSpec>,
    pypi: Option<VersionSpecifiers>,
    build: Option<StringMatcher>,
}

impl<'a> Matcher<'a> {
    /// Compile `ban`, or say why it cannot be: a range must parse for every kind the ban applies to.
    pub fn new(ban: &'a Ban) -> Result<Self, String> {
        let conda_applies = ban.kind != Some(PackageKind::Pypi);
        let pypi_applies = ban.kind != Some(PackageKind::Conda);
        if ban.build.is_some() && !conda_applies {
            return Err("`build` applies to conda packages only, not with kind = \"pypi\"".into());
        }
        let mut conda = None;
        let mut pypi = None;
        if let Some(range) = &ban.version {
            if conda_applies {
                conda = Some(VersionSpec::from_str(range, ParseStrictness::Lenient).map_err(|err| {
                    format!(
                        "version {range:?} is not a conda version range ({}); set kind = \"pypi\" if it is PEP 440",
                        reason(&err)
                    )
                })?);
            }
            if pypi_applies {
                pypi = Some(VersionSpecifiers::from_str(range).map_err(|err| {
                    format!(
                        "version {range:?} is not a PEP 440 range ({}); set kind = \"conda\" if it is conda's",
                        reason(&err)
                    )
                })?);
            }
        }
        let build = match &ban.build {
            Some(pattern) => Some(
                StringMatcher::from_str(pattern)
                    .map_err(|err| format!("build {pattern:?} is not a pattern ({})", reason(&err)))?,
            ),
            None => None,
        };
        Ok(Self {
            ban,
            conda,
            pypi,
            build,
        })
    }

    fn conda_version_matches(&self, version: Option<&str>) -> bool {
        match (&self.conda, version) {
            (None, _) => true,
            (Some(spec), Some(version)) => CondaVersion::from_str(version).is_ok_and(|version| spec.matches(&version)),
            (Some(_), None) => false,
        }
    }

    fn pypi_version_matches(&self, version: Option<&str>) -> bool {
        match (&self.pypi, version) {
            (None, _) => true,
            (Some(spec), Some(version)) => PypiVersion::from_str(version).is_ok_and(|version| spec.contains(&version)),
            (Some(_), None) => false,
        }
    }

    /// Why `fact` is banned, if it is: the message.
    pub fn matches(&self, fact: &Fact) -> Option<String> {
        let ban = self.ban;
        let conda_applies = ban.kind != Some(PackageKind::Pypi);
        let pypi_applies = ban.kind != Some(PackageKind::Conda);
        let pypi_name = normalize_pypi_name(&ban.name);
        match fact.kind {
            Kind::CondaBinary | Kind::CondaSource => {
                if conda_applies
                    && fact.name.eq_ignore_ascii_case(&ban.name)
                    && self.conda_version_matches(fact.version.as_deref())
                    && self
                        .build
                        .as_ref()
                        .is_none_or(|b| fact.build.as_deref().is_some_and(|build| b.matches(build)))
                {
                    return Some("is banned".into());
                }
                if pypi_applies && self.build.is_none() {
                    for (name, version) in fact.stated_purls.iter().filter_map(|purl| pypi_purl(purl)) {
                        if normalize_pypi_name(&name) == pypi_name && self.pypi_version_matches(version.as_deref()) {
                            let provided = version.map(|v| format!("{name} {v}")).unwrap_or(name);
                            return Some(format!("provides PyPI {provided}, which is banned"));
                        }
                    }
                }
                None
            }
            Kind::Pypi => (pypi_applies
                && normalize_pypi_name(&fact.name) == pypi_name
                && self.pypi_version_matches(fact.version.as_deref()))
            .then(|| "is banned".into()),
        }
    }
}

/// The name and version of a `pkg:pypi/<name>@<version>` purl.
fn pypi_purl(purl: &str) -> Option<(String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:pypi/")?;
    let rest = rest.split(['?', '#']).next()?;
    match rest.split_once('@') {
        Some((name, version)) => Some((name.to_string(), Some(version.to_string()))),
        None => Some((rest.to_string(), None)),
    }
}

struct Deny;

/// The `bans.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(Deny)]
}

impl Rule for Deny {
    fn id(&self) -> &'static str {
        "bans.deny"
    }

    fn summary(&self) -> &'static str {
        "No package, or package version, the policy bans"
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let Some(bans) = &policy.bans else {
            return Vec::new();
        };
        // Policy::parse has compiled every ban already; one that fails here was built by hand and is skipped.
        let matchers: Vec<Matcher<'_>> = bans.deny.iter().filter_map(|ban| Matcher::new(ban).ok()).collect();
        let mut findings = Vec::new();
        for fact in &facts.packages {
            let Some((matcher, what)) = matchers.iter().find_map(|m| m.matches(fact).map(|what| (m, what))) else {
                continue;
            };
            let ban = matcher.ban;
            let mut message = what;
            if let Some(version) = &ban.version {
                message.push_str(&format!(" (version {version})"));
            }
            if let Some(reason) = &ban.reason {
                message.push_str(&format!(": {reason}"));
            }
            let help = match &ban.use_instead {
                Some(other) => format!("use {other} instead"),
                None => "remove it, or lift the ban in [bans] deny".into(),
            };
            findings.push(Finding {
                rule: self.id(),
                severity: Severity::Error,
                package: Some(fact.name.clone()),
                version: fact.version.clone(),
                environment: facts.environment.clone(),
                platform: facts.platform.clone(),
                file: File::Lockfile,
                line: None,
                message,
                help: Some(help),
                advisory: Vec::new(),
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(name: &str, version: &str, kind: Kind, build: Option<&str>, purls: &[&str]) -> Fact {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        let mut fact = crate::lockfile::read(&lock, "default", Some("linux-64"))
            .unwrap()
            .packages
            .remove(0);
        fact.name = name.into();
        fact.version = Some(version.into());
        fact.kind = kind;
        fact.build = build.map(str::to_string);
        fact.stated_purls = purls.iter().map(|p| p.to_string()).collect();
        fact
    }

    fn policy(toml: &str) -> Policy {
        Policy::parse(toml, "p.toml").unwrap()
    }

    fn banned(policy_toml: &str, packages: Vec<Fact>) -> Vec<(String, String)> {
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages,
        };
        Deny.check(&policy(policy_toml), &facts)
            .into_iter()
            .map(|f| (f.package.unwrap(), f.message))
            .collect()
    }

    #[test]
    fn a_name_ban_matches_either_kind_by_name() {
        let got = banned(
            "[bans]\ndeny = [{ name = \"pycrypto\", reason = \"unmaintained\", use-instead = \"pycryptodome\" }]\n",
            vec![
                fact("pycrypto", "2.6.1", Kind::Pypi, None, &[]),
                fact("PyCrypto", "2.6.1", Kind::Pypi, None, &[]),
                fact("pycrypto", "2.6.1", Kind::CondaBinary, Some("py_0"), &[]),
                fact("pycryptodome", "3.20", Kind::Pypi, None, &[]),
            ],
        );
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(got[0].1, "is banned: unmaintained");
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages: vec![fact("pycrypto", "2.6.1", Kind::Pypi, None, &[])],
        };
        let finding = Deny.check(
            &policy("[bans]\ndeny = [{ name = \"pycrypto\", use-instead = \"pycryptodome\" }]\n"),
            &facts,
        );
        assert_eq!(finding[0].help.as_deref(), Some("use pycryptodome instead"));
        let finding = Deny.check(&policy("[bans]\ndeny = [{ name = \"pycrypto\" }]\n"), &facts);
        assert_eq!(
            finding[0].help.as_deref(),
            Some("remove it, or lift the ban in [bans] deny")
        );
    }

    #[test]
    fn a_version_range_is_compared_by_rattler_for_conda_and_pep440_for_pypi() {
        let ban = "[bans]\ndeny = [{ name = \"openssl\", version = \"<3\", reason = \"EOL\" }]\n";
        let got = banned(
            ban,
            vec![
                fact("openssl", "1.1.1w", Kind::CondaBinary, Some("hd590300_0"), &[]),
                fact("openssl", "3.0.15", Kind::CondaBinary, Some("hb9d3cd8_0"), &[]),
            ],
        );
        assert_eq!(
            got,
            [("openssl".to_string(), "is banned (version <3): EOL".to_string())]
        );
        // Conda's rules, not PEP 440's: letters order alphabetically (1.1.1v < 1.1.1w < 1.1.1x), and a letter sorts
        // before the bare number, so 1.1.1w is below 1.1.1. A plain string comparison gets both wrong.
        let below_x = "[bans]\ndeny = [{ name = \"openssl\", version = \"<1.1.1x\", kind = \"conda\" }]\n";
        let packages =
            ["1.1.1v", "1.1.1w", "1.1.1x", "1.1.1", "3.0.15"].map(|v| fact("openssl", v, Kind::CondaBinary, None, &[]));
        let versions: Vec<String> = Deny
            .check(
                &policy(below_x),
                &Facts {
                    environment: "default".into(),
                    platform: "linux-64".into(),
                    packages: packages.to_vec(),
                },
            )
            .into_iter()
            .map(|f| f.version.unwrap())
            .collect();
        assert_eq!(versions, ["1.1.1v", "1.1.1w"]);
        let below_bare = "[bans]\ndeny = [{ name = \"openssl\", version = \"<1.1.1\", kind = \"conda\" }]\n";
        assert_eq!(
            banned(
                below_bare,
                vec![fact("openssl", "1.1.1w", Kind::CondaBinary, None, &[])]
            )
            .len(),
            1
        );
        let pypi = "[bans]\ndeny = [{ name = \"urllib3\", version = \"<2\" }]\n";
        let got = banned(
            pypi,
            vec![
                fact("urllib3", "1.26.20", Kind::Pypi, None, &[]),
                fact("urllib3", "2.2.3", Kind::Pypi, None, &[]),
            ],
        );
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn a_build_string_pattern_is_matched_by_rattler() {
        let ban = "[bans]\ndeny = [{ name = \"pytorch\", build = \"*cuda*\", reason = \"CPU-only workspace\" }]\n";
        let got = banned(
            ban,
            vec![
                fact(
                    "pytorch",
                    "2.5.1",
                    Kind::CondaBinary,
                    Some("cuda126_py312h1763f6d_303"),
                    &[],
                ),
                fact("pytorch", "2.5.1", Kind::CondaBinary, Some("cpu_mkl_py312_h0"), &[]),
                fact("pytorch", "2.5.1", Kind::CondaBinary, None, &[]),
            ],
        );
        assert_eq!(got.len(), 1, "{got:?}");
    }

    #[test]
    fn a_kind_limits_a_ban_to_conda_or_pypi() {
        let both = vec![
            fact("six", "1.16.0", Kind::CondaBinary, None, &[]),
            fact("six", "1.16.0", Kind::Pypi, None, &[]),
        ];
        let conda = banned("[bans]\ndeny = [{ name = \"six\", kind = \"conda\" }]\n", both.clone());
        let pypi = banned("[bans]\ndeny = [{ name = \"six\", kind = \"pypi\" }]\n", both.clone());
        let either = banned("[bans]\ndeny = [{ name = \"six\" }]\n", both);
        assert_eq!((conda.len(), pypi.len(), either.len()), (1, 1, 2));
    }

    #[test]
    fn a_conda_package_is_banned_for_the_pypi_package_it_provides() {
        let pytorch = || {
            fact(
                "pytorch",
                "2.5.1",
                Kind::CondaBinary,
                Some("cpu_0"),
                &["pkg:pypi/torch@2.5.1"],
            )
        };
        let got = banned(
            "[bans]\ndeny = [{ name = \"torch\", version = \"<2.6\" }]\n",
            vec![pytorch()],
        );
        assert_eq!(
            got,
            [(
                "pytorch".to_string(),
                "provides PyPI torch 2.5.1, which is banned (version <2.6)".to_string()
            )]
        );
        assert_eq!(
            banned(
                "[bans]\ndeny = [{ name = \"torch\", kind = \"pypi\" }]\n",
                vec![pytorch()]
            )
            .len(),
            1
        );
        assert!(
            banned(
                "[bans]\ndeny = [{ name = \"torch\", kind = \"conda\" }]\n",
                vec![pytorch()]
            )
            .is_empty()
        );
        assert!(
            banned(
                "[bans]\ndeny = [{ name = \"torch\", version = \">=2.6\" }]\n",
                vec![pytorch()]
            )
            .is_empty()
        );
        // A package that is both: conda `six` providing PyPI `six` is one finding, not two.
        let six = fact("six", "1.16.0", Kind::CondaBinary, None, &["pkg:pypi/six@1.16.0"]);
        assert_eq!(banned("[bans]\ndeny = [{ name = \"six\" }]\n", vec![six]).len(), 1);
        let unversioned = fact("tool", "1.0", Kind::CondaBinary, None, &["pkg:pypi/Tool_Name?x=1"]);
        assert_eq!(
            banned("[bans]\ndeny = [{ name = \"tool-name\" }]\n", vec![unversioned.clone()]).len(),
            1
        );
        assert!(
            banned(
                "[bans]\ndeny = [{ name = \"tool-name\", version = \"<2\" }]\n",
                vec![unversioned]
            )
            .is_empty()
        );
    }

    #[test]
    fn a_ban_that_cannot_be_compiled_is_a_policy_error() {
        for (toml, expected) in [
            (
                "[bans]\ndeny = [{ name = \"x\", version = \">=1.1.1w\" }]\n",
                "not a PEP 440 range",
            ),
            (
                "[bans]\ndeny = [{ name = \"x\", version = \"=>>1\", kind = \"conda\" }]\n",
                "not a conda version range",
            ),
            (
                "[bans]\ndeny = [{ name = \"x\", build = \"*cuda*\", kind = \"pypi\" }]\n",
                "conda packages only",
            ),
            (
                "[bans]\ndeny = [{ name = \"x\", build = \"^(unclosed$\" }]\n",
                "not a pattern",
            ),
        ] {
            let err = Policy::parse(toml, "p.toml").unwrap_err();
            assert!(err.to_string().contains(expected), "{toml}: {err}");
            assert!(err.to_string().contains("\"x\""), "{err}");
        }
        assert!(
            Policy::parse(
                "[bans]\ndeny = [{ name = \"x\", version = \">=1.1.1w\", kind = \"conda\" }]\n",
                "p.toml"
            )
            .is_ok()
        );
        assert!(Policy::parse("[bans]\ndeny = [{ title = \"x\" }]\n", "p.toml").is_err());
    }

    #[test]
    fn an_invalid_range_is_explained_in_one_line() {
        let err = Policy::parse(
            "[bans]\ndeny = [{ name = \"openssl\", version = \"<1.1.1w\" }]\n",
            "p.toml",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(!message.contains('\n'), "{message}");
        assert!(
            !message.contains('^') && !message.contains("Failed to parse"),
            "{message}"
        );
        assert!(
            message.contains("found `w`") && message.ends_with("set kind = \"conda\" if it is conda's"),
            "{message}"
        );
        assert_eq!(reason(&"first line:\n  second\n"), "first line");
        assert_eq!(reason(&"Failed to parse version: after `1`:"), "after `1`");
        assert_eq!(reason(&""), "");
    }

    #[test]
    fn a_ranged_ban_skips_a_package_without_a_version() {
        let mut source = fact("built", "1.0", Kind::CondaSource, None, &[]);
        source.version = None;
        assert!(
            banned(
                "[bans]\ndeny = [{ name = \"built\", version = \"<2\" }]\n",
                vec![source.clone()]
            )
            .is_empty()
        );
        assert_eq!(banned("[bans]\ndeny = [{ name = \"built\" }]\n", vec![source]).len(), 1);
        let mut wheel = fact("w", "1.0", Kind::Pypi, None, &[]);
        wheel.version = None;
        assert!(banned("[bans]\ndeny = [{ name = \"w\", version = \"<2\" }]\n", vec![wheel]).is_empty());
        assert_eq!(Deny.summary(), "No package, or package version, the policy bans");
        assert_eq!(pypi_purl("pkg:conda/x@1"), None);
    }
}
