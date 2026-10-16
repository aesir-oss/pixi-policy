//! `python.*`: the Python minor version every environment runs (#42). The rules read the conda `python` package
//! pixi.lock resolves for each environment and platform; any patch release of the standard matches it, and an
//! environment without Python is not checked (decided on #42). `requires-python` (#56) reads the pyproject's
//! `[project] requires-python` instead: it must not admit an older minor than the standard, and must admit the
//! standard.

use std::str::FromStr;

use pep440_rs::{Version, VersionSpecifiers};

use crate::lockfile::{Facts, Kind};
use crate::manifest::Manifest;

use crate::check::{File, Finding, Rule, Severity};
use crate::policy::{Action, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Older,
    Newer,
    RequiresPython,
}

struct PythonRule {
    which: Which,
}

/// The three `python.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [Which::Older, Which::Newer, Which::RequiresPython]
        .into_iter()
        .map(|which| Box::new(PythonRule { which }) as Box<dyn Rule>)
        .collect()
}

/// The major and minor version of a Python version string: `3.14.0rc1` is (3, 14).
fn minor(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor: String = parts.next()?.chars().take_while(char::is_ascii_digit).collect();
    Some((major, minor.parse().ok()?))
}

impl Rule for PythonRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::Older => "python.older",
            Which::Newer => "python.newer",
            Which::RequiresPython => "python.requires-python",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::Older => "No environment runs a Python older than the policy's standard",
            Which::Newer => "No environment runs a Python newer than the policy's standard",
            Which::RequiresPython => {
                "The pyproject's requires-python starts at the policy's standard Python and admits it"
            }
        }
    }

    fn check_manifest(&self, policy: &Policy, manifest: &Manifest) -> Vec<Finding> {
        match self.which {
            Which::RequiresPython => self.requires_python(policy, manifest),
            _ => Vec::new(),
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let Some(settings) = &policy.python else {
            return Vec::new();
        };
        let Some(standard) = settings.standard() else {
            return Vec::new();
        };
        let (action, wanted, word) = match self.which {
            Which::Older => (settings.older(), std::cmp::Ordering::Less, "older"),
            Which::Newer => (settings.newer(), std::cmp::Ordering::Greater, "newer"),
            Which::RequiresPython => return Vec::new(),
        };
        let severity = match action {
            Action::Error => Severity::Error,
            Action::Warn => Severity::Warning,
            Action::Allow => return Vec::new(),
        };
        facts
            .packages
            .iter()
            .filter(|fact| matches!(fact.kind, Kind::CondaBinary | Kind::CondaSource) && fact.name == "python")
            .filter_map(|fact| {
                let version = fact.version.as_deref()?;
                (minor(version)?.cmp(&standard) == wanted).then(|| Finding {
                    rule: self.id(),
                    severity,
                    package: Some(fact.name.clone()),
                    version: Some(version.to_string()),
                    environment: facts.environment.clone(),
                    platform: facts.platform.clone(),
                    file: File::Lockfile,
                    line: None,
                    message: format!("is {word} than the standard, Python {}.{}", standard.0, standard.1),
                    help: Some(format!(
                        "set python = \"{}.{}.*\" in the manifest and run `pixi lock`",
                        standard.0, standard.1
                    )),
                    advisory: Vec::new(),
                })
            })
            .collect()
    }
}

/// What is wrong with `spec` for a standard of `major.minor`: it admits an older minor, or does not admit the standard.
pub fn requires_python_problem(spec: &str, (major, minor): (u64, u64)) -> Option<String> {
    let Ok(specifiers) = VersionSpecifiers::from_str(spec) else {
        return Some(format!("is {spec:?}, which is not a PEP 440 specifier"));
    };
    let admits = |version: String| Version::from_str(&version).is_ok_and(|v| specifiers.contains(&v));
    let older = (0..minor)
        .rev()
        .map(|m| (major, m))
        .chain((major > 0).then_some((major - 1, 99)))
        .find(|(ma, mi)| [0, 99].iter().any(|patch| admits(format!("{ma}.{mi}.{patch}"))));
    if let Some((ma, mi)) = older {
        return Some(format!(
            "is {spec:?}, which admits Python {ma}.{mi}, older than the standard {major}.{minor}"
        ));
    }
    if ![0, 5, 99]
        .iter()
        .any(|patch| admits(format!("{major}.{minor}.{patch}")))
    {
        return Some(format!(
            "is {spec:?}, which excludes Python {major}.{minor}, the standard"
        ));
    }
    None
}

impl PythonRule {
    fn requires_python(&self, policy: &Policy, manifest: &Manifest) -> Vec<Finding> {
        let Some(settings) = policy.python.as_ref().filter(|p| p.requires_python.unwrap_or(false)) else {
            return Vec::new();
        };
        let (Some(standard), Some((spec, line))) = (settings.standard(), &manifest.requires_python) else {
            return Vec::new();
        };
        requires_python_problem(spec, standard)
            .map(|problem| Finding {
                rule: self.id(),
                severity: Severity::Error,
                package: None,
                version: None,
                environment: String::new(),
                platform: String::new(),
                file: File::Pyproject,
                line: Some(*line),
                message: format!("requires-python {problem}"),
                help: Some(format!(
                    "set requires-python = \">={}.{}\" in [project]",
                    standard.0, standard.1
                )),
                advisory: Vec::new(),
            })
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_python_starts_at_the_standard_and_admits_it() {
        let problem = |spec: &str| requires_python_problem(spec, (3, 14));
        for ok in [">=3.14", ">=3.14,<4", "~=3.14", "==3.14.*", ">=3.14.2", ">=3.14,<3.16"] {
            assert_eq!(problem(ok), None, "{ok}");
        }
        assert_eq!(
            problem(">=3.12").unwrap(),
            "is \">=3.12\", which admits Python 3.13, older than the standard 3.14"
        );
        assert!(problem(">=2.7").unwrap().contains("admits Python 3.13"));
        assert!(
            problem(">=3.15")
                .unwrap()
                .contains("excludes Python 3.14, the standard")
        );
        assert!(problem("<3.14").unwrap().contains("admits Python 3.13"), "older first");
        assert!(problem(">=3.14,<3.14").unwrap().contains("excludes"));
        assert!(problem(">=three").unwrap().contains("not a PEP 440 specifier"));
    }

    #[test]
    fn minor_reads_major_and_minor() {
        assert_eq!(minor("3.14.0"), Some((3, 14)));
        assert_eq!(minor("3.14.0rc1"), Some((3, 14)));
        assert_eq!(minor("3.9"), Some((3, 9)));
        assert_eq!(minor("3.15a1"), Some((3, 15)));
        assert_eq!(minor("3"), None);
        assert_eq!(minor("x.y"), None);
    }

    #[test]
    fn summaries_say_what_each_rule_checks() {
        let rules = rules();
        assert_eq!(
            rules.iter().map(|r| r.id()).collect::<Vec<_>>(),
            ["python.older", "python.newer", "python.requires-python"]
        );
        assert!(rules.iter().all(|r| !r.summary().is_empty()));
    }
}
