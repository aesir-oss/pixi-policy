//! `hygiene.*`: what an environment should not hold (#11). `conda-pypi-duplicate` reports a PyPI package whose
//! distribution a conda package in the same environment already provides. A conda package's PyPI names are the purls
//! pixi.lock states for it and, for a conda-forge package it states none for, conda-forge's mapping (decided on #11).
//! The mapping is read only when some environment needs it; when it cannot be read, `hygiene.unavailable` fails the
//! check and the rule still compares what pixi.lock states.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use rattler_lock::LockFile;

use crate::advisories::{Client, Endpoints, Lookup, Mapping, mapped, needs_mapping};
use crate::check::{File, Finding, Rule, Severity};
use crate::lockfile::{self, Fact, Facts, Kind};
use crate::policy::Policy;
use crate::purl::normalize_pypi_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    CondaPypiDuplicate,
    Unavailable,
}

struct HygieneRule {
    which: Which,
    mapping: Option<Arc<Mapping>>,
}

/// The two `hygiene.*` rules, with conda-forge's mapping when it was read.
pub fn rules(mapping: Option<Arc<Mapping>>) -> Vec<Box<dyn Rule>> {
    [Which::CondaPypiDuplicate, Which::Unavailable]
        .into_iter()
        .map(|which| {
            Box::new(HygieneRule {
                which,
                mapping: mapping.clone(),
            }) as Box<dyn Rule>
        })
        .collect()
}

/// The name of a `pkg:pypi/<name>@<version>` purl.
fn pypi_name(purl: &str) -> Option<&str> {
    let rest = purl.strip_prefix("pkg:pypi/")?;
    rest.split(['@', '?', '#']).next().filter(|name| !name.is_empty())
}

/// The normalized PyPI names a conda package provides.
fn provides(fact: &Fact, mapping: Option<&Mapping>) -> Vec<String> {
    let stated = fact.stated_purls.iter().filter_map(|purl| pypi_name(purl));
    let mut names: Vec<String> = stated
        .chain(mapped(fact, mapping).iter().map(String::as_str))
        .map(normalize_pypi_name)
        .collect();
    names.sort();
    names.dedup();
    names
}

impl Rule for HygieneRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::CondaPypiDuplicate => "hygiene.conda-pypi-duplicate",
            Which::Unavailable => "hygiene.unavailable",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::CondaPypiDuplicate => "No PyPI package is one a conda package in the same environment provides",
            Which::Unavailable => "conda-forge's PyPI mapping cannot be read, so some conda packages were not compared",
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let on = policy.hygiene.as_ref().is_some_and(|h| h.conda_pypi_duplicate());
        if self.which != Which::CondaPypiDuplicate || !on {
            return Vec::new();
        }
        let mut conda: BTreeMap<String, &Fact> = BTreeMap::new();
        for fact in facts.packages.iter().filter(|fact| fact.kind != Kind::Pypi) {
            for name in provides(fact, self.mapping.as_deref()) {
                conda.entry(name).or_insert(fact);
            }
        }
        facts
            .packages
            .iter()
            .filter(|fact| fact.kind == Kind::Pypi)
            .filter_map(|fact| {
                let provider = conda.get(&normalize_pypi_name(&fact.name))?;
                let version = provider.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
                Some(Finding {
                    rule: self.id(),
                    severity: Severity::Error,
                    package: Some(fact.name.clone()),
                    version: fact.version.clone(),
                    environment: facts.environment.clone(),
                    platform: facts.platform.clone(),
                    file: File::Lockfile,
                    line: None,
                    message: format!("is also installed from conda, as {}{version}", provider.name),
                    help: Some(
                        "both are installed into the environment, one over the other: keep the conda package and \
                         drop the PyPI one, or the other way round"
                            .into(),
                    ),
                    advisory: Vec::new(),
                })
            })
            .collect()
    }
}

/// The `hygiene.unavailable` finding for a mapping that could not be read, with `message`.
pub fn unavailable(message: &str) -> Finding {
    Finding {
        rule: "hygiene.unavailable",
        severity: Severity::Error,
        package: None,
        version: None,
        environment: String::new(),
        platform: String::new(),
        file: File::Lockfile,
        line: None,
        message: format!(
            "conda-forge packages pixi.lock states no PyPI names for were not compared with PyPI packages: {message}"
        ),
        help: Some(
            "check the network and proxy settings, or point PIXI_POLICY_MAPPING_URL at a mirror; with \
             PIXI_POLICY_OFFLINE, run once online first to fill the cache"
                .into(),
        ),
        advisory: Vec::new(),
    }
}

/// Whether some environment of `lock` holds PyPI packages and a conda-forge package only the mapping names.
fn mapping_needed(lock: &LockFile) -> Result<bool, String> {
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment).map_err(|err| err.to_string())? {
            let facts = lockfile::read(lock, &environment, Some(&platform)).map_err(|err| err.to_string())?;
            let pypi = facts.packages.iter().any(|fact| fact.kind == Kind::Pypi);
            if pypi && facts.packages.iter().any(needs_mapping) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Read conda-forge's mapping when the policy's `[hygiene]` needs it for `lock`: `None` when it does not, the
/// mapping or why it cannot be read when it does.
pub fn gather(lock: &LockFile, policy: &Policy, lookup: &Lookup<'_>) -> Option<Result<Mapping, String>> {
    if !policy.hygiene.as_ref().is_some_and(|h| h.conda_pypi_duplicate()) {
        return None;
    }
    match mapping_needed(lock) {
        Ok(false) => None,
        Ok(true) => Some(lookup.mapping()),
        Err(message) => Some(Err(message)),
    }
}

/// [`gather`] with the network, the cache and the mirror the environment gives.
pub fn gather_from_env(lock: &LockFile, policy: &Policy) -> Option<Result<Mapping, String>> {
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
    gather(lock, policy, &lookup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purl_names_its_package() {
        assert_eq!(pypi_name("pkg:pypi/msgpack@1.1.0"), Some("msgpack"));
        assert_eq!(pypi_name("pkg:pypi/PyYAML?x=1"), Some("PyYAML"));
        assert_eq!(pypi_name("pkg:conda/x@1"), None);
        assert_eq!(pypi_name("pkg:pypi/"), None);
    }

    #[test]
    fn summaries_say_what_each_rule_checks() {
        let rules = rules(None);
        assert_eq!(
            rules.iter().map(|r| r.id()).collect::<Vec<_>>(),
            ["hygiene.conda-pypi-duplicate", "hygiene.unavailable"]
        );
        assert!(rules.iter().all(|r| !r.summary().is_empty()));
        assert!(unavailable("offline").message.ends_with(": offline"));
    }
}
