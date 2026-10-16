//! `freshness.*`: how old and how far behind conda packages are (#2). `build-age` reads the build time pixi.lock
//! records; `majors-behind` compares the version with the newest release in the package's own channel; `archived`
//! asks whether conda-forge has archived the feedstock that builds it. The channel data is [`crate::freshness`]'s,
//! looked up once before the rules run. A package the data says nothing about is `freshness.unknown`, and data that
//! cannot be read at all is `freshness.unavailable`, an error: missing data is never a pass (#2). PyPI packages from
//! pypi.org are checked the same way with `pypi` (#52): the upload time of the locked file, and the newest release
//! PyPI lists.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rattler_lock::LockFile;

use crate::check::{File, Finding, Rule, Severity};
use crate::freshness::{Client, Endpoints, Feedstock, Feedstocks, Key, Lookup, PypiReleases, Releases, major};
use crate::lockfile::{self, Fact, Facts, Kind};
use crate::policy::{Freshness, Policy, Unknown};
use crate::purl::normalize_pypi_name;
use crate::waivers::Date;

/// What the freshness rules judge: the time of the check, and the channel data the policy asked for.
#[derive(Debug, Default)]
pub struct Data {
    /// Seconds since 1970.
    pub now: i64,
    pub releases: Option<Releases>,
    pub feedstocks: Option<Feedstocks>,
    pub pypi: Option<PypiReleases>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    BuildAge,
    MajorsBehind,
    Archived,
    Unknown,
    Unavailable,
}

struct FreshnessRule {
    which: Which,
    data: Option<Arc<Data>>,
}

/// The five `freshness.*` rules, judging `data`; without it they find nothing.
pub fn rules(data: Option<Arc<Data>>) -> Vec<Box<dyn Rule>> {
    [
        Which::BuildAge,
        Which::MajorsBehind,
        Which::Archived,
        Which::Unknown,
        Which::Unavailable,
    ]
    .into_iter()
    .map(|which| {
        Box::new(FreshnessRule {
            which,
            data: data.clone(),
        }) as Box<dyn Rule>
    })
    .collect()
}

/// The channel a conda package came from, its subdir and name.
fn key(fact: &Fact) -> Option<Key> {
    Some(Key {
        channel: fact.channel_url.clone()?,
        subdir: fact.subdir.clone()?,
        name: fact.name.clone(),
    })
}

fn conda_forge(fact: &Fact) -> bool {
    fact.channel.as_deref() == Some("conda-forge")
}

/// What one package gets: the rule, the message and the help.
type Said = (Which, String, &'static str);

/// Why a PyPI package cannot be checked against pypi.org, if it cannot.
fn off_pypi(fact: &Fact) -> Option<String> {
    if fact.location_is_path || fact.location.starts_with("file:") {
        return Some("it is installed from a local path".into());
    }
    if fact.location.starts_with("git+") {
        return Some("it is built from a git repository".into());
    }
    match fact.index_host.as_deref() {
        Some("pypi.org") => None,
        Some(host) => Some(format!(
            "it comes from {host}; pixi-policy reads PyPI release data from pypi.org only"
        )),
        None => Some("it is installed from a URL, not an index".into()),
    }
}

/// What `settings` say about a PyPI package.
fn judge_pypi(settings: &Freshness, data: &Data, fact: &Fact) -> Vec<Said> {
    let mut out = Vec::new();
    if !settings.pypi() || (settings.max_build_age_days.is_none() && settings.max_majors_behind.is_none()) {
        return out;
    }
    if let Some(why) = off_pypi(fact) {
        out.push((
            Which::Unknown,
            format!("{why}, so how old and how far behind it is is unknown"),
            "waive it if it does not matter",
        ));
        return out;
    }
    let Some(releases) = &data.pypi else {
        return out;
    };
    let Some(project) = releases.project(&normalize_pypi_name(&fact.name)) else {
        out.push((
            Which::Unknown,
            "PyPI has no project by its name, so how old and how far behind it is is unknown".into(),
            "check where it comes from, or waive it",
        ));
        return out;
    };
    if let Some(max) = settings.max_build_age_days {
        match fact.sha256.as_ref().and_then(|sha| project.uploads.get(sha)) {
            None => out.push((
                Which::Unknown,
                "PyPI lists no upload of the file pixi.lock locks, so its age is unknown".into(),
                "relock it from pypi.org, or waive it",
            )),
            Some(&uploaded) => {
                let days = (data.now - uploaded).div_euclid(86_400);
                if days > i64::from(max) {
                    out.push((
                        Which::BuildAge,
                        format!(
                            "uploaded to PyPI {}, {days} days ago, more than max-build-age-days ({max})",
                            Date::from_days(uploaded.div_euclid(86_400))
                        ),
                        "update it to a newer release, or waive it",
                    ));
                }
            }
        }
    }
    if let (Some(max), Some(newest)) = (settings.max_majors_behind, project.newest.as_deref()) {
        let current = fact.version.as_deref().unwrap_or_default();
        match (major(current), major(newest)) {
            (Some(have), Some(top)) if top.saturating_sub(have) > u64::from(max) => out.push((
                Which::MajorsBehind,
                format!(
                    "{} major versions behind {newest}, the newest on PyPI, more than max-majors-behind ({max})",
                    top - have
                ),
                "upgrade it, or waive it while the upgrade is planned",
            )),
            (Some(_), Some(_)) => {}
            _ => out.push((
                Which::Unknown,
                format!("cannot tell the major version of {current} or {newest}, so how far behind it is is unknown"),
                "waive it if it does not matter",
            )),
        }
    }
    out
}

/// Everything `settings` say about `fact`.
fn judge(settings: &Freshness, data: &Data, fact: &Fact) -> Vec<Said> {
    let mut out = Vec::new();
    if fact.kind == Kind::Pypi {
        return judge_pypi(settings, data, fact);
    }
    if fact.kind != Kind::CondaBinary {
        return out;
    }
    if let Some(max) = settings.max_build_age_days {
        match fact.timestamp {
            None => out.push((
                Which::Unknown,
                "pixi.lock records no build time for it, so its build age is unknown".into(),
                "rebuild or update it so its record has a timestamp, or waive it",
            )),
            Some(built) => {
                let days = (data.now - built).div_euclid(86_400);
                if days > i64::from(max) {
                    out.push((
                        Which::BuildAge,
                        format!(
                            "built {}, {days} days ago, more than max-build-age-days ({max})",
                            Date::from_days(built.div_euclid(86_400))
                        ),
                        "update it to a newer build, ask its maintainers for a rebuild, or waive it",
                    ));
                }
            }
        }
    }
    if let (Some(max), Some(releases), Some(key)) = (settings.max_majors_behind, &data.releases, key(fact)) {
        let channel = fact.channel.as_deref().unwrap_or(&key.channel);
        match releases.newest(&key) {
            None => {}
            Some(None) => out.push((
                Which::Unknown,
                format!(
                    "{channel}'s {} and noarch repodata do not list it, so how far behind it is is unknown",
                    key.subdir
                ),
                "check where it comes from, or waive it",
            )),
            Some(Some(newest)) => {
                let current = fact.version.as_deref().unwrap_or_default();
                match (major(current), major(&newest)) {
                    (Some(have), Some(top)) if top.saturating_sub(have) > u64::from(max) => {
                        let behind = top - have;
                        out.push((
                            Which::MajorsBehind,
                            format!(
                                "{behind} major versions behind {newest}, the newest in {channel}, more than \
                                 max-majors-behind ({max})"
                            ),
                            "upgrade it, or waive it while the upgrade is planned",
                        ));
                    }
                    (Some(_), Some(_)) => {}
                    _ => out.push((
                        Which::Unknown,
                        format!(
                            "cannot tell the major version of {current} or {newest}, so how far behind it is is unknown"
                        ),
                        "waive it if it does not matter",
                    )),
                }
            }
        }
    }
    if let Some(feedstocks) = data
        .feedstocks
        .as_ref()
        .filter(|_| settings.archived() && conda_forge(fact))
    {
        match feedstocks.of(&fact.name) {
            Feedstock::Active => {}
            Feedstock::Archived(names) => out.push((
                Which::Archived,
                format!(
                    "its conda-forge feedstock {} is archived, so it gets no more builds or fixes",
                    names
                        .iter()
                        .map(|name| format!("{name}-feedstock"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "move to a maintained package, or waive it",
            )),
            Feedstock::Unknown => out.push((
                Which::Unknown,
                "conda-forge's feedstock outputs name no feedstock that builds it, so whether it is archived is unknown"
                    .into(),
                "waive it if it does not matter",
            )),
        }
    }
    out
}

impl Rule for FreshnessRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::BuildAge => "freshness.build-age",
            Which::MajorsBehind => "freshness.majors-behind",
            Which::Archived => "freshness.archived",
            Which::Unknown => "freshness.unknown",
            Which::Unavailable => "freshness.unavailable",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::BuildAge => "A package was built, or uploaded to PyPI, longer ago than max-build-age-days",
            Which::MajorsBehind => {
                "A package is more major versions behind its channel's or PyPI's newest than allowed"
            }
            Which::Archived => "A conda-forge package comes from an archived feedstock",
            Which::Unknown => "The channel or PyPI data says nothing about a package a freshness rule checks",
            Which::Unavailable => {
                "The channel or PyPI data cannot be read, so no package could be checked for freshness"
            }
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let (Some(settings), Some(data)) = (&policy.freshness, &self.data) else {
            return Vec::new();
        };
        let severity = match self.which {
            Which::Unknown => match settings.unknown() {
                Unknown::Allow => return Vec::new(),
                Unknown::Warn => Severity::Warning,
                Unknown::Error => Severity::Error,
            },
            _ => Severity::Error,
        };
        let mut out = Vec::new();
        for fact in &facts.packages {
            for (which, message, help) in judge(settings, data, fact) {
                if which == self.which {
                    out.push(Finding {
                        rule: self.id(),
                        severity,
                        package: Some(fact.name.clone()),
                        version: fact.version.clone(),
                        environment: facts.environment.clone(),
                        platform: facts.platform.clone(),
                        file: File::Lockfile,
                        line: None,
                        message,
                        help: Some(help.into()),
                        advisory: Vec::new(),
                    });
                }
            }
        }
        out
    }
}

/// The `freshness.unavailable` finding for a lookup that failed with `message`.
pub fn unavailable(message: &str) -> Finding {
    Finding {
        rule: "freshness.unavailable",
        severity: Severity::Error,
        package: None,
        version: None,
        environment: String::new(),
        platform: String::new(),
        file: File::Lockfile,
        line: None,
        message: format!("no package could be checked for freshness: {message}"),
        help: Some(
            "check the network and proxy settings, or point PIXI_POLICY_FEEDSTOCKS_URL, \
             PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL and PIXI_POLICY_PYPI_URL at mirrors; with PIXI_POLICY_OFFLINE, run once \
             online first to fill the cache"
                .into(),
        ),
        advisory: Vec::new(),
    }
}

/// Look up what `settings` need for every conda package of every environment of `lock`. On failure, the data the
/// lockfile alone gives (build ages) and why the rest is missing.
pub fn gather(lock: &LockFile, settings: &Freshness, lookup: &Lookup<'_>) -> (Data, Option<String>) {
    let now = lookup
        .now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut data = Data { now, ..Data::default() };
    let mut keys = BTreeSet::new();
    let mut projects = BTreeSet::new();
    let mut any_conda_forge = false;
    for environment in lockfile::environment_names(lock) {
        let Ok(platforms) = lockfile::platform_names(lock, &environment) else {
            continue;
        };
        for platform in platforms {
            let Ok(facts) = lockfile::read(lock, &environment, Some(&platform)) else {
                continue;
            };
            for fact in facts.packages.iter().filter(|fact| fact.kind == Kind::CondaBinary) {
                keys.extend(key(fact).into_iter().flat_map(Releases::wanted));
                any_conda_forge |= conda_forge(fact);
            }
            for fact in facts.packages.iter().filter(|fact| fact.kind == Kind::Pypi) {
                if off_pypi(fact).is_none() {
                    projects.insert(normalize_pypi_name(&fact.name));
                }
            }
        }
    }
    if settings.max_majors_behind.is_some() {
        match lookup.releases(&keys) {
            Ok(releases) => data.releases = Some(releases),
            Err(err) => return (data, Some(err)),
        }
    }
    let limits = settings.max_build_age_days.is_some() || settings.max_majors_behind.is_some();
    if settings.pypi() && limits && !projects.is_empty() {
        match lookup.pypi(&projects) {
            Ok(pypi) => data.pypi = Some(pypi),
            Err(err) => return (data, Some(err)),
        }
    }
    if settings.archived() && any_conda_forge {
        match lookup.feedstocks() {
            Ok(feedstocks) => data.feedstocks = Some(feedstocks),
            Err(err) => return (data, Some(err)),
        }
    }
    (data, None)
}

/// [`gather`] with the network, the cache and the mirrors the environment gives; `None` when the policy has no
/// `[freshness]`.
pub fn gather_from_env(lock: &LockFile, policy: &Policy) -> Option<(Data, Option<String>)> {
    let settings = policy.freshness.as_ref()?;
    let fetch = crate::fetch::Settings::from_env();
    let endpoints = Endpoints::from_env();
    let client: &dyn Client = &crate::freshness::Http;
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

    fn facts() -> Facts {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/freshness/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        lockfile::read(&lock, "default", Some("linux-64")).unwrap()
    }

    fn settings(text: &str) -> Freshness {
        Policy::parse(&format!("[freshness]\n{text}"), "p.toml")
            .unwrap()
            .freshness
            .unwrap()
    }

    fn said(settings: &Freshness, data: &Data, fact: &Fact) -> Vec<(Which, String)> {
        judge(settings, data, fact)
            .into_iter()
            .map(|(which, message, _)| (which, message))
            .collect()
    }

    #[test]
    fn a_pypi_package_is_judged_by_its_upload_and_pypis_newest() {
        let mut fact = facts().packages[0].clone();
        fact.kind = Kind::Pypi;
        fact.name = "Old_Thing".into();
        fact.version = Some("1.2.0".into());
        fact.sha256 = Some("aa".into());
        fact.location = "https://files.pythonhosted.org/packages/old_thing-1.2.0-py3-none-any.whl".into();
        fact.index_host = Some("pypi.org".into());
        let project = crate::freshness::Project {
            newest: Some("4.0.1".into()),
            uploads: [("aa".to_string(), 10 * 86_400)].into(),
        };
        let data = Data {
            now: 1000 * 86_400,
            pypi: Some(PypiReleases([("old-thing".to_string(), project)].into())),
            ..Data::default()
        };
        let found = said(
            &settings("max-build-age-days = 365\nmax-majors-behind = 1\n"),
            &data,
            &fact,
        );
        assert_eq!(
            found.iter().map(|(which, _)| *which).collect::<Vec<_>>(),
            [Which::BuildAge, Which::MajorsBehind]
        );
        assert!(
            found[0].1.starts_with("uploaded to PyPI 1970-01-11, 990 days ago"),
            "{found:?}"
        );
        assert!(
            found[1]
                .1
                .starts_with("3 major versions behind 4.0.1, the newest on PyPI"),
            "{found:?}"
        );
        let mut relocked = fact.clone();
        relocked.sha256 = Some("bb".into());
        let found = said(&settings("max-build-age-days = 365\n"), &data, &relocked);
        assert!(
            matches!(found.as_slice(), [(Which::Unknown, m)] if m.contains("no upload of the file")),
            "{found:?}"
        );
        let mut unheard = fact.clone();
        unheard.name = "nobody".into();
        let found = said(&settings("max-majors-behind = 1\n"), &data, &unheard);
        assert!(
            matches!(found.as_slice(), [(Which::Unknown, m)] if m.starts_with("PyPI has no project")),
            "{found:?}"
        );
        let mut private = fact;
        private.index_host = Some("pypi.acme.internal".into());
        let found = said(&settings("max-majors-behind = 1\n"), &data, &private);
        assert!(
            matches!(found.as_slice(), [(Which::Unknown, m)] if m.contains("pypi.acme.internal")),
            "{found:?}"
        );
    }

    #[test]
    fn what_the_data_cannot_say_is_unknown() {
        let facts = facts();
        let jinja2 = facts.packages.iter().find(|p| p.name == "jinja2").unwrap();
        let data = Data {
            now: 0,
            releases: Some(Releases::default()),
            feedstocks: Some(Feedstocks::parse(r#"{"active":["x"]}"#, "{}").unwrap()),
            pypi: None,
        };
        let mut undated = jinja2.clone();
        undated.timestamp = None;
        let all = settings("max-build-age-days = 1\nmax-majors-behind = 1\n");
        let found = said(&all, &data, &undated);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|(which, _)| *which == Which::Unknown));
        assert!(found[0].1.starts_with("pixi.lock records no build time"));
        assert!(
            found[1]
                .1
                .starts_with("conda-forge's feedstock outputs name no feedstock")
        );
        // Not looked up at all (a key the lookup never had): nothing to say.
        let mut listed = Releases::default();
        listed.0.insert(key(jinja2).unwrap(), None);
        let data = Data {
            releases: Some(listed),
            ..data
        };
        let found = said(&settings("max-majors-behind = 1\narchived = false\n"), &data, jinja2);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("do not list it"), "{found:?}");
        let mut odd = Releases::default();
        odd.0.insert(key(jinja2).unwrap(), Some("abc".into()));
        let data = Data {
            releases: Some(odd),
            ..data
        };
        let found = said(&settings("max-majors-behind = 1\narchived = false\n"), &data, jinja2);
        assert!(found[0].1.starts_with("cannot tell the major version"), "{found:?}");
    }

    #[test]
    fn unknown_takes_its_severity_from_the_policy_and_pypi_can_be_left_out() {
        let facts = facts();
        let data = Arc::new(Data {
            now: 0,
            releases: None,
            feedstocks: Some(Feedstocks::parse(r#"{"active":["x"]}"#, "{}").unwrap()),
            pypi: None,
        });
        let rule = |which| FreshnessRule {
            which,
            data: Some(data.clone()),
        };
        let policy = |text: &str| Policy::parse(&format!("[freshness]\n{text}"), "p.toml").unwrap();
        let warn = rule(Which::Unknown).check(&policy(""), &facts);
        assert!(!warn.is_empty() && warn.iter().all(|f| f.severity == Severity::Warning));
        let error = rule(Which::Unknown).check(&policy("unknown = \"error\"\n"), &facts);
        assert!(error.iter().all(|f| f.severity == Severity::Error));
        assert!(
            rule(Which::Unknown)
                .check(&policy("unknown = \"allow\"\n"), &facts)
                .is_empty()
        );
        assert!(rule(Which::Archived).check(&Policy::default(), &facts).is_empty());
        let mut pypi = facts.packages[0].clone();
        pypi.kind = Kind::Pypi;
        assert!(judge(&settings("max-build-age-days = 0\npypi = false\n"), &data, &pypi).is_empty());
        let off = judge(&settings("max-build-age-days = 0\n"), &data, &pypi);
        assert!(
            matches!(off.as_slice(), [(Which::Unknown, message, _)] if message.starts_with("it is installed from a URL")),
            "{off:?}"
        );
        for rule in rules(None) {
            assert!(rule.id().starts_with("freshness.") && !rule.summary().is_empty());
        }
        let finding = unavailable("down");
        assert_eq!(
            (finding.rule, finding.severity),
            ("freshness.unavailable", Severity::Error)
        );
    }
}
