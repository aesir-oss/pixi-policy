//! `advisories.*`: known vulnerabilities (#3). An advisory fails when it is at or above `fail-on`, known exploited
//! (CISA's KEV catalog) or at or above the `epss` threshold; one with no severity is reported by `unknown`. The data
//! is [`crate::advisories`]'s, looked up once for every package of every environment before the rules run. When it
//! cannot be read, `advisories.unavailable` fails the check rather than pass a workspace nobody looked at (decided
//! on #3).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use rattler_lock::LockFile;

use crate::advisories::{Advisory, Client, Data, Endpoints, Level, Lookup, Wanted, identities};
use crate::check::{File, Finding, Rule, Severity};
use crate::lockfile::{self, Facts};
use crate::policy::{Action, Advisories, Policy, PypiMapping, Unknown};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Vulnerable,
    Unknown,
    Unavailable,
}

struct AdvisoryRule {
    which: Which,
    data: Option<Arc<Data>>,
}

/// The three `advisories.*` rules, judging `data`; without it they find nothing.
pub fn rules(data: Option<Arc<Data>>) -> Vec<Box<dyn Rule>> {
    [Which::Vulnerable, Which::Unknown, Which::Unavailable]
        .into_iter()
        .map(|which| {
            Box::new(AdvisoryRule {
                which,
                data: data.clone(),
            }) as Box<dyn Rule>
        })
        .collect()
}

/// What `settings` make of `advisory`: the rule, the severity and why.
fn judge(settings: &Advisories, advisory: &Advisory) -> Option<(Which, Severity, Vec<String>)> {
    let mut reasons = Vec::new();
    let mut error = false;
    if advisory.level >= settings.fail_on() {
        reasons.push(format!("{} severity", advisory.level.name()));
        error = true;
    }
    if advisory.known_exploited && settings.known_exploited() != Action::Allow {
        reasons.push("known exploited".to_string());
        error |= settings.known_exploited() == Action::Error;
    }
    if let (Some(threshold), Some(score)) = (settings.epss, advisory.epss)
        && score >= threshold
    {
        reasons.push(format!("EPSS {score}"));
        error = true;
    }
    if !reasons.is_empty() {
        let severity = if error { Severity::Error } else { Severity::Warning };
        return Some((Which::Vulnerable, severity, reasons));
    }
    if advisory.level != Level::Unknown {
        return None;
    }
    let severity = match settings.unknown() {
        Unknown::Allow => return None,
        Unknown::Warn => Severity::Warning,
        Unknown::Error => Severity::Error,
    };
    Some((Which::Unknown, severity, vec!["unknown severity".to_string()]))
}

impl Rule for AdvisoryRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::Vulnerable => "advisories.vulnerable",
            Which::Unknown => "advisories.unknown",
            Which::Unavailable => "advisories.unavailable",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::Vulnerable => {
                "A package has a known vulnerability at or above fail-on, known exploited, or above the EPSS threshold"
            }
            Which::Unknown => "A package has a known vulnerability whose severity no advisory gives",
            Which::Unavailable => "The advisory data cannot be read, so no package could be checked",
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let (Some(settings), Some(data)) = (&policy.advisories, &self.data) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for fact in &facts.packages {
            for (advisory, fixed) in data.for_package(fact) {
                let Some((which, severity, reasons)) = judge(settings, advisory) else {
                    continue;
                };
                if which != self.which {
                    continue;
                }
                let cve = advisory.aliases.iter().find(|alias| alias.starts_with("CVE-"));
                let named = match cve {
                    Some(cve) => format!("{} ({cve})", advisory.id),
                    None => advisory.id.clone(),
                };
                let summary = advisory
                    .summary
                    .as_deref()
                    .map(|summary| format!(": {summary}"))
                    .unwrap_or_default();
                let help = match fixed {
                    Some(fixed) => format!("upgrade to {fixed} or later; see {}", advisory.url()),
                    None => format!(
                        "no fixed version is known: see {}, and waive it with advisory = {:?} if it does not affect \
                         this workspace",
                        advisory.url(),
                        advisory.id
                    ),
                };
                out.push(Finding {
                    rule: self.id(),
                    severity,
                    package: Some(fact.name.clone()),
                    version: fact.version.clone(),
                    environment: facts.environment.clone(),
                    platform: facts.platform.clone(),
                    file: File::Lockfile,
                    line: None,
                    message: format!("{named}, {}{summary}", reasons.join(", ")),
                    help: Some(help),
                    advisory: advisory.names(),
                });
            }
        }
        out
    }
}

/// The `advisories.unavailable` finding for a lookup that failed with `message`.
pub fn unavailable(message: &str) -> Finding {
    Finding {
        rule: "advisories.unavailable",
        severity: Severity::Error,
        package: None,
        version: None,
        environment: String::new(),
        platform: String::new(),
        file: File::Lockfile,
        line: None,
        message: format!("no package could be checked for advisories: {message}"),
        help: Some(
            "check the network and proxy settings, or point PIXI_POLICY_OSV_URL, PIXI_POLICY_KEV_URL, \
             PIXI_POLICY_EPSS_URL and PIXI_POLICY_MAPPING_URL at mirrors; with PIXI_POLICY_OFFLINE, run once online \
             first to fill the cache"
                .into(),
        ),
        advisory: Vec::new(),
    }
}

/// Look up the advisories for every package of every environment of `lock`, as `settings` ask.
pub fn gather(lock: &LockFile, settings: &Advisories, lookup: &Lookup<'_>) -> Result<Data, String> {
    let mapping = match settings.pypi_mapping() {
        PypiMapping::Prefix => Some(lookup.mapping()?),
        PypiMapping::Lock => None,
    };
    let mut purls = BTreeSet::new();
    for environment in lockfile::environment_names(lock) {
        let platforms = lockfile::platform_names(lock, &environment).map_err(|err| err.to_string())?;
        for platform in platforms {
            let facts = lockfile::read(lock, &environment, Some(&platform)).map_err(|err| err.to_string())?;
            for fact in &facts.packages {
                purls.extend(identities(fact, mapping.as_ref()));
            }
        }
    }
    let wanted = Wanted {
        kev: settings.known_exploited() != Action::Allow,
        epss: settings.epss.is_some(),
    };
    let mut data = lookup.run(&purls, wanted)?;
    data.mapping = mapping;
    Ok(data)
}

/// [`gather`] with the network, the cache and the mirrors the environment gives; `None` when the policy has no
/// `[advisories]`.
pub fn gather_from_env(lock: &LockFile, policy: &Policy) -> Option<Result<Data, String>> {
    let settings = policy.advisories.as_ref()?;
    let fetch = crate::fetch::Settings::from_env();
    let endpoints = Endpoints::from_env();
    let client: &dyn Client = &crate::advisories::Http;
    let lookup = Lookup {
        endpoints: &endpoints,
        cache: fetch.cache.as_deref(),
        offline: fetch.offline,
        client,
        now: SystemTime::now(),
    };
    Some(gather(lock, settings, &lookup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisories::Mapping;

    fn advisory(level: Level, known_exploited: bool, epss: Option<f64>) -> Advisory {
        Advisory {
            id: "GHSA-1".into(),
            aliases: vec!["CVE-2026-1".into()],
            summary: None,
            level,
            known_exploited,
            epss,
        }
    }

    fn settings(text: &str) -> Advisories {
        Policy::parse(&format!("[advisories]\n{text}"), "p.toml")
            .unwrap()
            .advisories
            .unwrap()
    }

    #[test]
    fn fail_on_known_exploited_and_epss_each_fail_an_advisory() {
        let defaults = settings("");
        let judged = |s: &Advisories, a: Advisory| {
            judge(s, &a).map(|(which, severity, reasons)| (which, severity, reasons.join(", ")))
        };
        assert_eq!(judged(&defaults, advisory(Level::Medium, false, None)), None);
        assert_eq!(
            judged(&defaults, advisory(Level::High, false, None)),
            Some((Which::Vulnerable, Severity::Error, "high severity".into()))
        );
        assert_eq!(
            judged(&defaults, advisory(Level::Low, true, Some(0.2))),
            Some((Which::Vulnerable, Severity::Error, "known exploited".into()))
        );
        let warn = settings("known-exploited = \"warn\"\nepss = 0.1\n");
        assert_eq!(
            judged(&warn, advisory(Level::Low, true, None)),
            Some((Which::Vulnerable, Severity::Warning, "known exploited".into()))
        );
        assert_eq!(
            judged(&warn, advisory(Level::Critical, true, Some(0.1))),
            Some((
                Which::Vulnerable,
                Severity::Error,
                "critical severity, known exploited, EPSS 0.1".into()
            ))
        );
        let allow = settings("known-exploited = \"allow\"\nfail-on = \"critical\"\n");
        assert_eq!(judged(&allow, advisory(Level::High, true, Some(0.9))), None);
    }

    #[test]
    fn an_advisory_with_no_severity_is_unknown_unless_something_else_fails_it() {
        let judged = |text: &str, a: Advisory| judge(&settings(text), &a).map(|(which, severity, _)| (which, severity));
        assert_eq!(
            judged("", advisory(Level::Unknown, false, None)),
            Some((Which::Unknown, Severity::Warning))
        );
        assert_eq!(
            judged("unknown = \"error\"\n", advisory(Level::Unknown, false, None)),
            Some((Which::Unknown, Severity::Error))
        );
        assert_eq!(
            judged("unknown = \"allow\"\n", advisory(Level::Unknown, false, None)),
            None
        );
        assert_eq!(
            judged("", advisory(Level::Unknown, true, None)),
            Some((Which::Vulnerable, Severity::Error))
        );
        assert_eq!(judged("fail-on = \"low\"\n", advisory(Level::None, false, None)), None);
    }

    fn fixture_facts() -> Facts {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/advisories/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        lockfile::read(&lock, "default", Some("linux-64")).unwrap()
    }

    #[test]
    fn a_package_is_looked_up_by_its_pypi_identities() {
        let facts = fixture_facts();
        let fact = |name: &str| facts.packages.iter().find(|p| p.name == name).unwrap().clone();
        let mapping = Mapping::parse(r#"{"jinja2":"Jinja2","markupsafe":"other","openssl":null}"#).unwrap();
        assert_eq!(identities(&fact("urllib3"), None), ["pkg:pypi/urllib3@1.26.4"]);
        // The lockfile's purl wins over the mapping, which is for packages it states none for.
        assert_eq!(
            identities(&fact("markupsafe"), Some(&mapping)),
            ["pkg:pypi/markupsafe@3.0.4"]
        );
        assert_eq!(identities(&fact("jinja2"), Some(&mapping)), ["pkg:pypi/jinja2@3.1.2"]);
        assert!(identities(&fact("jinja2"), None).is_empty());
        assert!(identities(&fact("openssl"), Some(&mapping)).is_empty());
        let mut elsewhere = fact("jinja2");
        elsewhere.channel_url = Some("https://example.com/internal".into());
        assert!(identities(&elsewhere, Some(&mapping)).is_empty());
        let mut from_git = fact("urllib3");
        from_git.location = "git+https://github.com/urllib3/urllib3?rev=abc".into();
        assert!(identities(&from_git, None).is_empty());
        let mut unversioned = fact("urllib3");
        unversioned.version = None;
        assert!(identities(&unversioned, None).is_empty());
    }

    #[test]
    fn without_data_or_a_table_the_rules_find_nothing_and_each_has_an_id_and_summary() {
        let facts = fixture_facts();
        let policy = Policy::parse("[advisories]\n", "p.toml").unwrap();
        for rule in rules(None) {
            assert!(rule.check(&policy, &facts).is_empty());
            assert!(rule.id().starts_with("advisories.") && !rule.summary().is_empty());
        }
        let data = Some(Arc::new(Data::default()));
        for rule in rules(data) {
            assert!(rule.check(&Policy::default(), &facts).is_empty());
        }
    }

    #[test]
    fn an_unavailable_finding_fails_and_names_no_package() {
        let finding = unavailable("OSV is down");
        assert_eq!(
            (finding.rule, finding.severity),
            ("advisories.unavailable", Severity::Error)
        );
        assert!(finding.package.is_none() && finding.message.ends_with("OSV is down"));
    }
}
