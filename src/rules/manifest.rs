//! `manifest.*`: pixi.toml hygiene (#64). Writing a `[manifest]` table turns on `wildcard-spec` and `python-pinned`
//! (each can be set to false); `required-platforms` runs when its list is given (decided on #64). Findings point at the
//! manifest line.

use std::collections::BTreeSet;
use std::str::FromStr;

use rattler_conda_types::{ParseStrictness, Version, VersionSpec};

use crate::check::{File, Finding, Rule, Severity};
use crate::manifest::{Dependency, DependencyKind, Manifest};
use crate::policy::Policy;

/// Whether a conda spec lets Python move by no more than its patch version: the versions it accepts, sampled across
/// every minor from 2.0 to 4.30 and around every version the spec itself names, all share one minor (`3.12.*`,
/// `>=3.12,<3.13`, `3.12.5`).
pub fn python_pinned(text: &str) -> bool {
    let Ok(spec) = VersionSpec::from_str(text, ParseStrictness::Lenient) else {
        return false;
    };
    let mut samples: Vec<String> = Vec::new();
    for major in 2..=4 {
        for minor in 0..=30 {
            samples.extend([0, 1, 99].map(|patch| format!("{major}.{minor}.{patch}")));
        }
    }
    // Each version the spec names, and the next minor and major above it, so an open upper bound reaches a second
    // minor however high it starts.
    for token in text
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|t| t.trim_matches('.'))
    {
        let parts: Vec<u64> = token.split('.').filter_map(|p| p.parse().ok()).collect();
        let (Some(&major), minor) = (parts.first(), parts.get(1).copied().unwrap_or(0)) else {
            continue;
        };
        samples.push(token.to_string());
        samples.push(format!("{major}.{}.0", minor + 1));
        samples.push(format!("{}.0.0", major + 1));
    }
    let minors: BTreeSet<(String, String)> = samples
        .iter()
        .filter_map(|sample| Version::from_str(sample).ok().map(|version| (sample, version)))
        .filter(|(_, version)| spec.matches(version))
        .map(|(sample, _)| {
            let mut parts = sample.split('.');
            (
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("0").to_string(),
            )
        })
        .collect();
    minors.len() == 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    WildcardSpec,
    PythonPinned,
    RequiredPlatforms,
}

struct ManifestRule {
    which: Which,
}

/// The three `manifest.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [Which::WildcardSpec, Which::PythonPinned, Which::RequiredPlatforms]
        .into_iter()
        .map(|which| Box::new(ManifestRule { which }) as Box<dyn Rule>)
        .collect()
}

impl ManifestRule {
    fn finding(&self, manifest: &Manifest, package: Option<&str>, line: u32, message: String, help: &str) -> Finding {
        Finding {
            rule: self.id(),
            severity: Severity::Error,
            package: package.map(str::to_string),
            version: None,
            environment: String::new(),
            platform: String::new(),
            file: if manifest.pyproject {
                File::Pyproject
            } else {
                File::Manifest
            },
            line: Some(line),
            message,
            help: Some(help.into()),
        }
    }

    fn dependency(&self, manifest: &Manifest, dep: &Dependency, message: String, help: &str) -> Finding {
        self.finding(manifest, Some(&dep.name), dep.line, message, help)
    }
}

impl Rule for ManifestRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::WildcardSpec => "manifest.wildcard-spec",
            Which::PythonPinned => "manifest.python-pinned",
            Which::RequiredPlatforms => "manifest.required-platforms",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::WildcardSpec => "No dependency is given as `*`",
            Which::PythonPinned => "Python is constrained to one minor version or narrower",
            Which::RequiredPlatforms => "The workspace lists every platform the policy requires",
        }
    }

    fn check_manifest(&self, policy: &Policy, manifest: &Manifest) -> Vec<Finding> {
        let Some(settings) = &policy.manifest else {
            return Vec::new();
        };
        match self.which {
            Which::WildcardSpec if settings.wildcard_spec.unwrap_or(true) => manifest
                .dependencies
                .iter()
                .filter(|dep| dep.spec.as_deref().map(str::trim) == Some("*"))
                .map(|dep| {
                    self.dependency(
                        manifest,
                        dep,
                        format!("is given as \"*\" in [{}]", dep.table),
                        "give it a version range, for example the one `pixi add` writes",
                    )
                })
                .collect(),
            Which::PythonPinned if settings.python_pinned.unwrap_or(true) => manifest
                .dependencies
                .iter()
                .filter(|dep| dep.kind == DependencyKind::Conda && dep.name.eq_ignore_ascii_case("python"))
                .filter(|dep| !dep.spec.as_deref().is_some_and(python_pinned))
                .map(|dep| {
                    let spec = dep.spec.as_deref().unwrap_or("no version");
                    self.dependency(
                        manifest,
                        dep,
                        format!("is not pinned to one minor version in [{}] ({spec})", dep.table),
                        "pin the minor version, for example python = \"3.12.*\"",
                    )
                })
                .collect(),
            Which::RequiredPlatforms => {
                let Some(required) = &settings.required_platforms else {
                    return Vec::new();
                };
                let (listed, line) = manifest.platforms.clone().unwrap_or((Vec::new(), 1));
                required
                    .iter()
                    .filter(|platform| !listed.contains(platform))
                    .map(|platform| {
                        self.finding(
                            manifest,
                            None,
                            line,
                            format!(
                                "platform {platform} is required by the policy but not in the workspace's platforms"
                            ),
                            "add it to platforms in [workspace] and run `pixi lock`",
                        )
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Manifest {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifest")
            .join(name);
        Manifest::load(&dir.join("pixi.toml")).unwrap()
    }

    fn found(policy: &str, manifest: &Manifest) -> Vec<(&'static str, Option<String>, Option<u32>)> {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        rules()
            .iter()
            .flat_map(|rule| rule.check_manifest(&policy, manifest))
            .map(|f| (f.rule, f.package, f.line))
            .collect()
    }

    const ALL: &str = "[manifest]\nrequired-platforms = [\"linux-64\", \"osx-arm64\", \"win-64\"]\n";

    #[test]
    fn the_passing_fixture_passes_every_rule() {
        assert!(found(ALL, &fixture("pass")).is_empty());
    }

    #[test]
    fn the_failing_fixture_fails_each_rule_at_its_line() {
        let got = found(ALL, &fixture("fail"));
        assert_eq!(
            got,
            [
                ("manifest.wildcard-spec", Some("numpy".to_string()), Some(8)),
                ("manifest.wildcard-spec", Some("requests".to_string()), Some(11)),
                ("manifest.wildcard-spec", Some("ruff".to_string()), Some(14)),
                ("manifest.python-pinned", Some("python".to_string()), Some(7)),
                ("manifest.required-platforms", None, Some(4)),
                ("manifest.required-platforms", None, Some(4)),
            ]
        );
    }

    #[test]
    fn rules_follow_the_settings() {
        let fail = fixture("fail");
        assert!(found("", &fail).is_empty(), "no [manifest], no findings");
        let on = found("[manifest]\n", &fail);
        assert_eq!(
            on.len(),
            4,
            "wildcard-spec and python-pinned are on once [manifest] exists: {on:?}"
        );
        let off = found("[manifest]\nwildcard-spec = false\npython-pinned = false\n", &fail);
        assert!(off.is_empty(), "{off:?}");
        assert!(Policy::parse("[manifest]\nwildcard = true\n", "p.toml").is_err());
    }

    #[test]
    fn python_is_pinned_to_one_minor_or_narrower() {
        for spec in [
            "3.12.*",
            ">=3.12,<3.13",
            "3.12.5",
            "==3.12.5",
            "3.12",
            "~=3.12.0",
            ">=3.12.1,<3.12.4",
        ] {
            assert!(python_pinned(spec), "{spec}");
        }
        for spec in ["*", ">=3.10", "3.*", ">=3.11,<3.13", "<4", "not a spec !!", ">=9"] {
            assert!(!python_pinned(spec), "{spec}");
        }
    }

    #[test]
    fn findings_explain_and_name_the_file() {
        let policy = Policy::parse("[manifest]\nrequired-platforms = [\"win-64\"]\n", "p.toml").unwrap();
        let fail = fixture("fail");
        let all: Vec<Finding> = rules().iter().flat_map(|r| r.check_manifest(&policy, &fail)).collect();
        assert_eq!(all[0].message, "is given as \"*\" in [dependencies]");
        assert!(
            all.iter()
                .any(|f| f.message == "is not pinned to one minor version in [dependencies] (>=3.10)")
        );
        assert!(all.iter().any(|f| f.message.starts_with("platform win-64 is required")));
        assert!(
            all.iter()
                .all(|f| f.file == File::Manifest && f.severity == Severity::Error)
        );
        let pyproject = Manifest::parse("[tool.pixi.dependencies]\npython = \"*\"\n", true).unwrap();
        let findings: Vec<Finding> = rules()
            .iter()
            .flat_map(|r| r.check_manifest(&policy, &pyproject))
            .collect();
        assert!(findings.iter().all(|f| f.file == File::Pyproject));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "manifest.required-platforms" && f.line == Some(1)),
            "no platforms: line 1"
        );
        let summaries: Vec<&str> = rules().iter().map(|r| r.summary()).collect();
        assert!(summaries.iter().all(|s| !s.is_empty()));
        let unpinned = Manifest::parse("[dependencies]\npython = { channel = \"conda-forge\" }\n", false).unwrap();
        let findings: Vec<Finding> = rules()
            .iter()
            .flat_map(|r| r.check_manifest(&policy, &unpinned))
            .collect();
        assert!(findings.iter().any(|f| f.message.ends_with("(no version)")));
    }
}
