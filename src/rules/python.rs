//! `python.*`: the Python minor version every environment runs (#42). The rules read the conda `python` package
//! pixi.lock resolves for each environment and platform; any patch release of the standard matches it, and an
//! environment without Python is not checked (decided on #42).

use crate::lockfile::{Facts, Kind};

use crate::check::{File, Finding, Rule, Severity};
use crate::policy::{Action, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Older,
    Newer,
}

struct PythonRule {
    which: Which,
}

/// The two `python.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [Which::Older, Which::Newer]
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
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::Older => "No environment runs a Python older than the policy's standard",
            Which::Newer => "No environment runs a Python newer than the policy's standard",
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ["python.older", "python.newer"]
        );
        assert!(rules.iter().all(|r| !r.summary().is_empty()));
    }
}
