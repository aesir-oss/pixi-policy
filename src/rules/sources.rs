//! `sources.*`: where packages may come from (#61).
//!
//! Every package has one origin: a conda channel, a PyPI index, a git repository, a direct URL or a local path. Each
//! rule checks one kind against `[sources]`, and a key the policy leaves out restricts nothing.
//!
//! Channels are matched as `pixi.lock` records them. pixi's `mirrors` setting only changes where pixi downloads from,
//! so a mirrored channel is recorded, and matched, as the channel it mirrors. A channel given by name matches its
//! anaconda.org and prefix.dev URLs and nothing else (decided on #61): any other host must be listed by URL.

use crate::lockfile::{BuildSource, Fact, Facts, Kind};

use crate::check::{File, Finding, Rule, Severity};
use crate::policy::{Policy, Sources};

/// The hosts that serve a channel known by its name alone.
const NAMED_CHANNEL_HOSTS: [&str; 3] = [
    "https://conda.anaconda.org",
    "https://prefix.dev",
    "https://repo.prefix.dev",
];

/// Where a package comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Channel(String),
    Index(String),
    Git(String),
    Url(String),
    Path(String),
}

/// The origin of a package, as `pixi.lock` records it.
pub fn origin(fact: &Fact) -> Origin {
    let local = |location: &str| fact.location_is_path || location.starts_with("file:");
    match fact.kind {
        Kind::CondaBinary => match &fact.channel_url {
            Some(channel) => Origin::Channel(channel.clone()),
            None if local(&fact.location) => Origin::Path(fact.location.clone()),
            None => Origin::Url(fact.location.clone()),
        },
        Kind::CondaSource => match &fact.build_source {
            Some(BuildSource::Git { url, .. }) => Origin::Git(url.clone()),
            Some(BuildSource::Url { url, .. }) => Origin::Url(url.clone()),
            Some(BuildSource::Path { path }) => Origin::Path(path.clone()),
            None => Origin::Path(fact.location.clone()),
        },
        Kind::Pypi => {
            if local(&fact.location) {
                Origin::Path(fact.location.clone())
            } else if fact.location.starts_with("git+") {
                Origin::Git(fact.location.clone())
            } else if let Some(index) = fact.index_url.as_ref().filter(|_| !fact.sdist) {
                Origin::Index(index.clone())
            } else {
                Origin::Url(fact.location.clone())
            }
        }
    }
}

/// A URL as compared: scheme and host in lower case, no trailing slash.
fn normalize(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest.split_once('/').map_or((rest, ""), |(host, path)| (host, path));
            let path = if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            };
            format!("{}://{}{path}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase())
        }
        None => url.to_string(),
    }
}

/// Whether `channel` (a URL from `pixi.lock`) is one of `allowed` (names or URLs).
pub fn channel_allowed(channel: &str, allowed: &[String]) -> bool {
    let channel = normalize(channel);
    allowed.iter().any(|entry| {
        if entry.contains("://") {
            normalize(entry) == channel
        } else {
            let name = entry.trim().trim_matches('/');
            NAMED_CHANNEL_HOSTS
                .iter()
                .any(|host| channel == format!("{host}/{name}"))
        }
    })
}

/// Whether every channel the `allowed-channels` entry `entry` names is also allowed by `allowed`: a name stands for its
/// anaconda.org and prefix.dev URLs.
pub fn channel_covered(entry: &str, allowed: &[String]) -> bool {
    if entry.contains("://") {
        return channel_allowed(entry, allowed);
    }
    let name = entry.trim().trim_matches('/');
    NAMED_CHANNEL_HOSTS
        .iter()
        .all(|host| channel_allowed(&format!("{host}/{name}"), allowed))
}

/// Whether `index` is one of `allowed`.
pub fn index_allowed(index: &str, allowed: &[String]) -> bool {
    let index = normalize(index);
    allowed.iter().any(|entry| normalize(entry) == index)
}

/// Which kind of origin a rule checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Channels,
    Indexes,
    Git,
    Url,
    Path,
}

struct SourceRule {
    check: Check,
}

/// The five `sources.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [Check::Channels, Check::Indexes, Check::Git, Check::Url, Check::Path]
        .into_iter()
        .map(|check| Box::new(SourceRule { check }) as Box<dyn Rule>)
        .collect()
}

impl SourceRule {
    /// What the rule says about one package's origin, if it objects: the message and the help.
    fn object(&self, sources: &Sources, origin: &Origin) -> Option<(String, String)> {
        let forbidden = |allowed: Option<bool>| allowed == Some(false);
        match (self.check, origin) {
            (Check::Channels, Origin::Channel(channel)) => {
                let allowed = sources.allowed_channels.as_deref()?;
                (!channel_allowed(channel, allowed)).then(|| {
                    (
                        format!("comes from channel {channel}, which the policy does not allow"),
                        "take it from an allowed channel, or add the channel to [sources] allowed-channels".into(),
                    )
                })
            }
            (Check::Indexes, Origin::Index(index)) => {
                let allowed = sources.allowed_indexes.as_deref()?;
                (!index_allowed(index, allowed)).then(|| {
                    (
                        format!("comes from index {index}, which the policy does not allow"),
                        "take it from an allowed index, or add the index to [sources] allowed-indexes".into(),
                    )
                })
            }
            (Check::Git, Origin::Git(url)) if forbidden(sources.allow_git) => Some((
                format!("comes from git ({url}), which the policy does not allow"),
                "depend on a released version from a channel or an index, or set [sources] allow-git = true".into(),
            )),
            (Check::Url, Origin::Url(url)) if forbidden(sources.allow_url) => Some((
                format!("comes from a direct URL ({url}), which the policy does not allow"),
                "depend on it through a channel or an index, or set [sources] allow-url = true".into(),
            )),
            (Check::Path, Origin::Path(path)) if forbidden(sources.allow_path) => Some((
                format!("comes from a local path ({path}), which the policy does not allow"),
                "publish it to a channel or an index, or set [sources] allow-path = true".into(),
            )),
            _ => None,
        }
    }
}

impl Rule for SourceRule {
    fn id(&self) -> &'static str {
        match self.check {
            Check::Channels => "sources.channels",
            Check::Indexes => "sources.indexes",
            Check::Git => "sources.git",
            Check::Url => "sources.url",
            Check::Path => "sources.path",
        }
    }

    fn summary(&self) -> &'static str {
        match self.check {
            Check::Channels => "Conda packages come only from the channels the policy allows",
            Check::Indexes => "PyPI packages come only from the indexes the policy allows",
            Check::Git => "No package comes from a git repository unless the policy allows it",
            Check::Url => "No package comes from a direct URL unless the policy allows it",
            Check::Path => "No package comes from a local path unless the policy allows it",
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let Some(sources) = &policy.sources else {
            return Vec::new();
        };
        facts
            .packages
            .iter()
            .filter_map(|fact| {
                let (message, help) = self.object(sources, &origin(fact))?;
                Some(Finding {
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
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        crate::lockfile::read(&lock, "default", Some("linux-64")).unwrap()
    }

    fn origin_of(facts: &Facts, name: &str) -> Origin {
        origin(facts.packages.iter().find(|f| f.name == name).unwrap())
    }

    fn found(policy: &str) -> Vec<(&'static str, String)> {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        let facts = facts();
        rules()
            .iter()
            .flat_map(|rule| rule.check(&policy, &facts))
            .map(|f| (f.rule, f.package.unwrap()))
            .collect()
    }

    #[test]
    fn every_kind_of_origin_is_told_apart() {
        let facts = facts();
        let cases = [
            (
                "libzlib",
                Origin::Channel("https://conda.anaconda.org/conda-forge/".into()),
            ),
            ("tzdata", Origin::Channel("https://prefix.dev/conda-forge/".into())),
            ("requests", Origin::Index("https://pypi.org/simple".into())),
            ("acme-client", Origin::Index("https://pypi.acme.internal/simple".into())),
            (
                "git-built",
                Origin::Git("https://github.com/example/git-built.git".into()),
            ),
            (
                "url-built",
                Origin::Url("https://example.com/url-built-2.0.0.tar.gz".into()),
            ),
            ("path-built", Origin::Path("../path-built".into())),
            (
                "urlpkg",
                Origin::Url("https://example.com/archives/urlpkg-1.0.tar.gz".into()),
            ),
            ("localpkg", Origin::Path("./libs/localpkg".into())),
        ];
        for (name, expected) in cases {
            assert_eq!(origin_of(&facts, name), expected, "{name}");
        }
        assert!(matches!(origin_of(&facts, "gitpkg"), Origin::Git(url) if url.starts_with("git+https://github.com")));
    }

    #[test]
    fn a_channel_name_matches_its_anaconda_and_prefix_spellings_only() {
        let allowed = vec!["conda-forge".to_string()];
        for url in [
            "https://conda.anaconda.org/conda-forge/",
            "https://conda.anaconda.org/conda-forge",
            "HTTPS://Conda.Anaconda.org/conda-forge/",
            "https://prefix.dev/conda-forge",
            "https://repo.prefix.dev/conda-forge/",
        ] {
            assert!(channel_allowed(url, &allowed), "{url}");
        }
        for url in [
            "https://evil.example/conda-forge",
            "https://conda.anaconda.org/conda-forge-fork",
            "https://conda.anaconda.org/bioconda",
            "http://conda.anaconda.org/conda-forge",
        ] {
            assert!(!channel_allowed(url, &allowed), "{url}");
        }
        let by_url = vec!["https://conda.acme.internal/prod/".to_string()];
        assert!(channel_allowed("https://conda.acme.internal/prod", &by_url));
        assert!(!channel_allowed("https://conda.acme.internal/dev", &by_url));
        assert!(index_allowed(
            "https://pypi.org/simple/",
            &["https://PyPI.org/simple".to_string()]
        ));
    }

    #[test]
    fn an_empty_or_absent_sources_table_finds_nothing() {
        assert!(found("").is_empty());
        assert!(found("[sources]\n").is_empty());
        assert!(found("[sources]\nallow-git = true\nallow-url = true\nallow-path = true\n").is_empty());
    }

    #[test]
    fn each_rule_finds_its_own_kind() {
        let policy = r#"
[sources]
allowed-channels = ["conda-forge", "https://conda.acme.internal/prod"]
allowed-indexes = ["https://pypi.org/simple", "https://pypi.acme.internal/simple"]
allow-git = false
allow-url = false
allow-path = false
"#;
        let mut got = found(policy);
        got.sort();
        let expected: Vec<(&str, String)> = [
            ("sources.channels", "samtools"),
            ("sources.git", "git-built"),
            ("sources.git", "gitpkg"),
            ("sources.indexes", "typosquat"),
            ("sources.path", "localpkg"),
            ("sources.path", "path-built"),
            ("sources.url", "url-built"),
            ("sources.url", "urlpkg"),
        ]
        .into_iter()
        .map(|(rule, name)| (rule, name.to_string()))
        .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn a_mirrored_channel_is_matched_as_the_channel_it_mirrors() {
        // The fixture's .pixi/config.toml mirrors conda-forge to mirror.example; pixi.lock still says conda-forge.
        let config = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/.pixi/config.toml"),
        )
        .unwrap();
        assert!(config.contains("https://mirror.example/conda-forge"));
        let by_name = found(
            "[sources]\nallowed-channels = [\"conda-forge\", \"https://conda.acme.internal/prod\", \"bioconda\"]\n",
        );
        assert!(by_name.is_empty(), "{by_name:?}");
        let mirror_only = found("[sources]\nallowed-channels = [\"https://mirror.example/conda-forge\"]\n");
        assert!(
            mirror_only.contains(&("sources.channels", "libzlib".to_string())),
            "{mirror_only:?}"
        );
    }

    #[test]
    fn a_finding_names_the_package_its_origin_and_what_to_do() {
        let policy = Policy::parse("[sources]\nallow-git = false\n", "p.toml").unwrap();
        let facts = facts();
        let rule = SourceRule { check: Check::Git };
        let finding = rule
            .check(&policy, &facts)
            .into_iter()
            .find(|f| f.package.as_deref() == Some("git-built"))
            .unwrap();
        assert_eq!(
            finding.message,
            "comes from git (https://github.com/example/git-built.git), which the policy does not allow"
        );
        assert_eq!(
            (
                finding.environment.as_str(),
                finding.platform.as_str(),
                finding.version.as_deref()
            ),
            ("default", "linux-64", Some("1.0.0"))
        );
        assert!(finding.help.unwrap().contains("allow-git = true"));
        let summaries: Vec<&str> = rules().iter().map(|r| r.summary()).collect();
        assert_eq!(summaries.len(), 5);
        assert!(summaries.iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn a_conda_archive_outside_a_channel_is_a_url_or_a_path() {
        let mut fact = facts().packages.into_iter().find(|f| f.name == "libzlib").unwrap();
        fact.channel_url = None;
        assert!(matches!(origin(&fact), Origin::Url(_)));
        fact.location = "file:///opt/pkgs/libzlib.conda".into();
        assert!(matches!(origin(&fact), Origin::Path(_)));
        let mut source = facts().packages.into_iter().find(|f| f.name == "path-built").unwrap();
        source.build_source = None;
        assert_eq!(origin(&source), Origin::Path("../path-built".into()));
    }
}
