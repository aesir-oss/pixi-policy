//! The advisory data `[advisories]` checks against (#3): OSV's advisories for every package with a PyPI identity,
//! rated from their CVSS vectors, with CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS scores on top.
//! These are the sources pixi-sbom's `--vulns` reads, read the same way, so both tools report the same advisories.
//! OSV has no conda ecosystem: a conda package is looked up by the PyPI purls pixi.lock states for it or, when the
//! lockfile states none, by conda-forge's conda-to-PyPI mapping (decided on #3).
//!
//! Everything is cached under the pixi-policy cache: OSV's answers for an hour, its records until OSV says they
//! changed, the catalog, the scores and the mapping for a day. Offline, a cached copy of any age stands in, and a
//! failed download falls back to a stale copy; with no copy at all the lookup fails, and the check with it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cvss;
use crate::lockfile::{Fact, Kind};

pub const OSV_URL: &str = "https://api.osv.dev";
pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
pub const MAPPING_URL: &str = "https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json";

/// How long OSV's answer for a purl is trusted: advisories are published every day.
const QUERY_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// How long the catalog, a score and the mapping are trusted: each is republished daily.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Purls per OSV `querybatch` request, the API's maximum.
const QUERY_BATCH: usize = 1000;
/// CVEs per EPSS request: the API pages at 100 rows.
const EPSS_BATCH: usize = 100;
/// OSV records fetched at once.
const WORKERS: usize = 8;
/// The largest answer read, in bytes.
const MAX_BYTES: u64 = 64 << 20;

/// How bad an advisory is, on the CVSS qualitative scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Nothing says how bad it is.
    Unknown,
    /// Rated as having no impact.
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// The words advisory databases use; GitHub's `moderate` is `medium`.
    fn parse(word: &str) -> Option<Self> {
        Some(match word.trim().to_ascii_lowercase().as_str() {
            "none" => Self::None,
            "low" => Self::Low,
            "medium" | "moderate" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => return None,
        })
    }

    /// The level of a CVSS base score.
    fn from_score(score: f64) -> Self {
        match score {
            0.0 => Self::None,
            s if s < 4.0 => Self::Low,
            s if s < 7.0 => Self::Medium,
            s if s < 9.0 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Where the data comes from: the public services, or the mirrors `PIXI_POLICY_OSV_URL`, `PIXI_POLICY_KEV_URL`,
/// `PIXI_POLICY_EPSS_URL` and `PIXI_POLICY_MAPPING_URL` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub osv: String,
    pub kev: String,
    pub epss: String,
    pub mapping: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            osv: OSV_URL.into(),
            kev: KEV_URL.into(),
            epss: EPSS_URL.into(),
            mapping: MAPPING_URL.into(),
        }
    }
}

impl Endpoints {
    pub fn from_env() -> Self {
        let var = |name: &str, default: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        Self {
            osv: var("PIXI_POLICY_OSV_URL", OSV_URL),
            kev: var("PIXI_POLICY_KEV_URL", KEV_URL),
            epss: var("PIXI_POLICY_EPSS_URL", EPSS_URL),
            mapping: var("PIXI_POLICY_MAPPING_URL", MAPPING_URL),
        }
    }
}

/// What a lookup needs from the network, so tests can answer for it.
pub trait Client: Sync {
    fn get(&self, url: &str) -> Result<String, String>;
    fn post(&self, url: &str, body: &str) -> Result<String, String>;
}

/// The network.
pub struct Http;

impl Client for Http {
    fn get(&self, url: &str) -> Result<String, String> {
        text(crate::fetch::get(url, MAX_BYTES)?)
    }

    fn post(&self, url: &str, body: &str) -> Result<String, String> {
        text(crate::fetch::post_json(url, body, MAX_BYTES)?)
    }
}

fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|_| "the answer is not UTF-8 text".to_string())
}

/// One advisory, merged from the OSV records that describe it (a GHSA and a PYSEC record sharing a CVE).
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    /// The other records' ids and every alias, sorted.
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub level: Level,
    /// In CISA's catalog of known exploited vulnerabilities, by one of its CVEs.
    pub known_exploited: bool,
    /// The highest EPSS score among its CVEs, when one was asked for.
    pub epss: Option<f64>,
}

impl Advisory {
    /// The id, then the aliases.
    pub fn names(&self) -> Vec<String> {
        std::iter::once(&self.id).chain(&self.aliases).cloned().collect()
    }

    /// Its page on osv.dev.
    pub fn url(&self) -> String {
        format!("https://osv.dev/vulnerability/{}", self.id)
    }

    fn cves(&self) -> impl Iterator<Item = String> + '_ {
        std::iter::once(&self.id)
            .chain(&self.aliases)
            .map(|name| name.to_ascii_uppercase())
            .filter(|name| name.starts_with("CVE-"))
    }
}

/// An advisory reported for a purl, and the version that fixes it there when OSV gives one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    advisory: usize,
    fixed: Option<String>,
}

/// conda package name to PyPI names, from conda-forge's mapping.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Mapping(HashMap<String, Vec<String>>);

impl Mapping {
    /// The mapping's JSON: conda name to a PyPI name, a list of them, or null.
    pub fn parse(text: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Names {
            One(String),
            Many(Vec<String>),
        }
        let raw: HashMap<String, Option<Names>> =
            serde_json::from_str(text).map_err(|err| format!("the conda-forge PyPI mapping is not JSON: {err}"))?;
        Ok(Self(
            raw.into_iter()
                .map(|(conda, names)| {
                    let names = match names {
                        Some(Names::One(name)) => vec![name],
                        Some(Names::Many(names)) => names,
                        None => Vec::new(),
                    };
                    (conda.to_lowercase(), names)
                })
                .collect(),
        ))
    }
}

/// Every advisory for the packages looked up.
#[derive(Debug, Default)]
pub struct Data {
    pub advisories: Vec<Advisory>,
    by_purl: HashMap<String, Vec<Hit>>,
    pub(crate) mapping: Option<Mapping>,
}

impl Data {
    /// The advisories for `fact`, each once, with the version that fixes it when OSV gives one.
    pub fn for_package(&self, fact: &Fact) -> Vec<(&Advisory, Option<&str>)> {
        let mut found: BTreeMap<usize, Option<&str>> = BTreeMap::new();
        for purl in identities(fact, self.mapping.as_ref()) {
            for hit in self.by_purl.get(&purl).into_iter().flatten() {
                let fixed = found.entry(hit.advisory).or_default();
                if fixed.is_none() {
                    *fixed = hit.fixed.as_deref();
                }
            }
        }
        found
            .into_iter()
            .map(|(index, fixed)| (&self.advisories[index], fixed))
            .collect()
    }
}

/// The purl OSV is asked about: type, namespace, name and version, without qualifiers or a subpath. `None` for a
/// conda purl, which OSV has no ecosystem for, and for one without a version.
fn queryable(purl: &str) -> Option<String> {
    let bare = purl.split(['?', '#']).next().unwrap_or(purl);
    (bare.starts_with("pkg:pypi/") && bare.contains('@')).then(|| bare.to_string())
}

/// The PyPI purls `fact` is looked up by: a PyPI package's own, unless it is built from a git checkout or a path,
/// whose code is not that release's; a conda package's stated PyPI purls, or, when the lockfile states none for a
/// conda-forge package, the ones `mapping` gives it.
pub fn identities(fact: &Fact, mapping: Option<&Mapping>) -> Vec<String> {
    let Some(version) = fact.version.as_deref() else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    match fact.kind {
        Kind::Pypi => {
            if !fact.location_is_path && !fact.location.starts_with("git+") {
                out.extend(queryable(&fact.purl));
            }
        }
        Kind::CondaBinary | Kind::CondaSource => {
            out.extend(fact.stated_purls.iter().filter_map(|purl| queryable(purl)));
            let conda_forge = fact
                .channel_url
                .as_deref()
                .is_some_and(|url| url.trim_end_matches('/').ends_with("/conda-forge"));
            if !fact.purls_from_lock && fact.kind == Kind::CondaBinary && conda_forge {
                let names = mapping.and_then(|mapping| mapping.0.get(&fact.name.to_lowercase()));
                out.extend(
                    names
                        .into_iter()
                        .flatten()
                        .filter_map(|name| crate::purl::pypi(name, version).ok()),
                );
            }
        }
    }
    out.into_iter().collect()
}

/// What to look up besides OSV.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wanted {
    pub kev: bool,
    pub epss: bool,
}

/// One lookup: where to ask, the cache, whether the network may be used, and the clock.
pub struct Lookup<'a> {
    pub endpoints: &'a Endpoints,
    pub cache: Option<&'a Path>,
    pub offline: bool,
    pub client: &'a dyn Client,
    pub now: SystemTime,
}

#[derive(Debug, Serialize)]
struct BatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Debug, Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueryPackage<'a> {
    purl: &'a str,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<QueryResult>,
}

#[derive(Debug, Default, Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
    next_page_token: Option<String>,
}

/// An advisory id with its last-modified stamp, as `querybatch` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VulnRef {
    id: String,
    #[serde(default)]
    modified: Option<String>,
}

/// A cached `querybatch` answer for one purl.
#[derive(Debug, Serialize, Deserialize)]
struct CachedQuery {
    purl: String,
    fetched_at: u64,
    vulns: Vec<VulnRef>,
}

/// `null` and a missing key both mean none, for list fields.
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The parts of an OSV record read here.
#[derive(Debug, Default, Deserialize)]
struct Record {
    id: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    aliases: Vec<String>,
    summary: Option<String>,
    modified: Option<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    severity: Vec<RecordSeverity>,
    #[serde(default, deserialize_with = "null_as_empty")]
    affected: Vec<RecordAffected>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RecordSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Debug, Default, Deserialize)]
struct RecordAffected {
    #[serde(default)]
    package: Option<RecordPackage>,
    #[serde(default, deserialize_with = "null_as_empty")]
    ranges: Vec<RecordRange>,
}

#[derive(Debug, Deserialize)]
struct RecordPackage {
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    events: Vec<BTreeMap<String, String>>,
}

impl Record {
    /// Its level, and whether a CVSS score gave it: the database's word, or a CVSS v3 vector's score, whichever is
    /// worse; a vector with no score here (v2, v4) counts as the database's word.
    fn level(&self) -> (Level, bool) {
        let word = self
            .database_specific
            .as_ref()
            .and_then(|db| db.get("severity"))
            .and_then(serde_json::Value::as_str)
            .and_then(Level::parse);
        let mut level = word.unwrap_or(Level::Unknown);
        let mut scored = false;
        for entry in &self.severity {
            if entry.kind == "CVSS_V3"
                && let Some(score) = cvss::v3_base_score(entry.score.trim())
            {
                level = level.max(Level::from_score(score));
                scored = true;
            }
        }
        (level, scored)
    }

    /// The smallest fixed version above `version` among the record's ranges for `purl`, or the first one listed when
    /// versions cannot be compared.
    fn fixed(&self, purl: &str) -> Option<String> {
        let (bare, version) = purl.split_once('@').unwrap_or((purl, ""));
        let mut fixed: Vec<String> = Vec::new();
        for affected in &self.affected {
            let same = affected
                .package
                .as_ref()
                .and_then(|package| package.purl.as_deref())
                .is_some_and(|p| p.split(['@', '?']).next().unwrap_or(p).eq_ignore_ascii_case(bare));
            if same {
                for range in affected.ranges.iter().filter(|range| range.kind != "GIT") {
                    fixed.extend(range.events.iter().filter_map(|event| event.get("fixed").cloned()));
                }
            }
        }
        let parse = |text: &str| text.parse::<rattler_conda_types::Version>().ok();
        let mut candidates: Vec<(rattler_conda_types::Version, &String)> =
            fixed.iter().filter_map(|f| parse(f).map(|v| (v, f))).collect();
        candidates.sort();
        let current = parse(version);
        let above = current.and_then(|current| candidates.iter().find(|(v, _)| *v > current));
        above
            .or(candidates.last())
            .map(|(_, f)| (*f).clone())
            .or_else(|| fixed.first().cloned())
    }
}

/// Whether two RFC 3339 stamps name the same microsecond: `querybatch` gives `modified` in microseconds and the
/// record in nanoseconds.
fn same_instant(a: &str, b: &str) -> bool {
    let micros = |stamp: &str| {
        let stamp = stamp.trim_end_matches('Z');
        let (head, fraction) = stamp.split_once('.').unwrap_or((stamp, ""));
        let digits: String = fraction.chars().take_while(char::is_ascii_digit).take(6).collect();
        format!("{head}.{digits:0<6}")
    };
    micros(a) == micros(b)
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Write a cache file; a cache that cannot be written only costs the next run a fetch.
fn keep(path: &Path, text: &str) {
    if let Err(err) = crate::fetch::store(path, text.as_bytes()) {
        tracing::debug!(path = %path.display(), %err, "cannot cache");
    }
}

impl Lookup<'_> {
    fn file(&self, parts: &[&str]) -> Option<PathBuf> {
        self.cache
            .map(|dir| parts.iter().fold(dir.join("advisories"), |path, part| path.join(part)))
    }

    fn offline_error(&self, what: &str) -> String {
        format!("{what} is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it")
    }

    /// A download kept for a day: the cached copy while it is younger (any age offline), else a fresh one, else the
    /// stale copy.
    fn daily(&self, name: &str, url: &str, what: &str) -> Result<String, String> {
        let file = self.file(&[name]);
        let cached = file.as_deref().and_then(|path| std::fs::read_to_string(path).ok());
        let age = file
            .as_deref()
            .and_then(|path| std::fs::metadata(path).and_then(|meta| meta.modified()).ok())
            .map(|modified| self.now.duration_since(modified).unwrap_or(Duration::ZERO));
        if let (Some(text), Some(age)) = (&cached, age)
            && (self.offline || age <= DAY)
        {
            return Ok(text.clone());
        }
        if self.offline {
            return Err(self.offline_error(what));
        }
        match self.client.get(url) {
            Ok(text) => {
                if let Some(path) = &file {
                    keep(path, &text);
                }
                Ok(text)
            }
            Err(err) => match cached {
                Some(text) => {
                    tracing::warn!(url, %err, "download failed; using the stale cached copy");
                    Ok(text)
                }
                None => Err(format!("cannot download {what} from {url}: {err}")),
            },
        }
    }

    /// conda-forge's conda-to-PyPI mapping.
    pub fn mapping(&self) -> Result<Mapping, String> {
        let text = self.daily(
            "pypi-mapping.json",
            &self.endpoints.mapping,
            "the conda-forge PyPI mapping",
        )?;
        Mapping::parse(&text)
    }

    /// Every advisory for `purls`, with what `wanted` adds.
    pub fn run(&self, purls: &BTreeSet<String>, wanted: Wanted) -> Result<Data, String> {
        let refs = self.query(purls)?;
        let mut modified: BTreeMap<&str, Option<&str>> = BTreeMap::new();
        for vulns in refs.values() {
            for vuln in vulns {
                modified.insert(&vuln.id, vuln.modified.as_deref());
            }
        }
        let ids: Vec<(&str, Option<&str>)> = modified.into_iter().collect();
        let records = self.records(&ids)?;
        let (mut advisories, owner) = merge(&records);
        let index: HashMap<&str, usize> = records.iter().map(|r| r.id.as_str()).zip(owner).collect();
        let mut by_purl: HashMap<String, Vec<Hit>> = HashMap::new();
        for (purl, vulns) in &refs {
            let hits = by_purl.entry((*purl).to_string()).or_default();
            for vuln in vulns {
                let record = records.iter().find(|r| r.id == vuln.id).expect("every id has a record");
                hits.push(Hit {
                    advisory: index[vuln.id.as_str()],
                    fixed: record.fixed(purl),
                });
            }
        }
        if wanted.kev && !advisories.is_empty() {
            let catalog = self.kev()?;
            for advisory in &mut advisories {
                let known = advisory.cves().any(|cve| catalog.contains(&cve));
                advisory.known_exploited = known;
            }
        }
        if wanted.epss {
            let cves: BTreeSet<String> = advisories.iter().flat_map(Advisory::cves).collect();
            let scores = self.epss(&cves)?;
            for advisory in &mut advisories {
                let best = advisory
                    .cves()
                    .filter_map(|cve| scores.get(&cve).copied())
                    .max_by(f64::total_cmp);
                advisory.epss = best;
            }
        }
        Ok(Data {
            advisories,
            by_purl,
            mapping: None,
        })
    }

    /// The advisory ids OSV gives each purl: cached answers younger than an hour (any age offline), the rest asked
    /// for in batches.
    fn query<'p>(&self, purls: &'p BTreeSet<String>) -> Result<BTreeMap<&'p str, Vec<VulnRef>>, String> {
        let mut out = BTreeMap::new();
        let mut pending = Vec::new();
        for purl in purls {
            let cached = self
                .query_file(purl)
                .and_then(|path| std::fs::read_to_string(path).ok())
                .and_then(|text| serde_json::from_str::<CachedQuery>(&text).ok());
            let fresh = |c: &CachedQuery| seconds(self.now).saturating_sub(c.fetched_at) < QUERY_MAX_AGE.as_secs();
            match cached {
                Some(cached) if self.offline || fresh(&cached) => {
                    out.insert(purl.as_str(), cached.vulns);
                }
                _ if self.offline => return Err(self.offline_error(&format!("OSV's answer for {purl}"))),
                _ => pending.push(purl.as_str()),
            }
        }
        let url = format!("{}/v1/querybatch", self.endpoints.osv.trim_end_matches('/'));
        for chunk in pending.chunks(QUERY_BATCH) {
            let mut tokens: Vec<Option<String>> = vec![None; chunk.len()];
            let mut done = vec![false; chunk.len()];
            let mut found: Vec<Vec<VulnRef>> = vec![Vec::new(); chunk.len()];
            while done.contains(&false) {
                let open: Vec<usize> = (0..chunk.len()).filter(|&i| !done[i]).collect();
                let body = serde_json::to_string(&BatchRequest {
                    queries: open
                        .iter()
                        .map(|&i| Query {
                            package: QueryPackage { purl: chunk[i] },
                            page_token: tokens[i].clone(),
                        })
                        .collect(),
                })
                .expect("a query is JSON");
                let text = self
                    .client
                    .post(&url, &body)
                    .map_err(|err| format!("cannot query OSV at {url}: {err}"))?;
                let response: BatchResponse = serde_json::from_str(&text)
                    .map_err(|err| format!("OSV at {url} answered with something that is not a query result: {err}"))?;
                let mut results = response.results.into_iter();
                for i in open {
                    // An answer shorter than the question counts as no advisories, not as a reason to ask forever.
                    let result = results.next().unwrap_or_default();
                    found[i].extend(result.vulns);
                    tokens[i] = result.next_page_token;
                    done[i] = tokens[i].is_none();
                }
            }
            for (purl, vulns) in chunk.iter().zip(found) {
                if let Some(path) = self.query_file(purl) {
                    let cached = CachedQuery {
                        purl: (*purl).to_string(),
                        fetched_at: seconds(self.now),
                        vulns: vulns.clone(),
                    };
                    keep(&path, &serde_json::to_string(&cached).expect("a cache entry is JSON"));
                }
                out.insert(purl, vulns);
            }
        }
        Ok(out)
    }

    fn query_file(&self, purl: &str) -> Option<PathBuf> {
        let name: String = purl
            .chars()
            .map(|c| match c {
                c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') => c,
                _ => '_',
            })
            .collect();
        self.file(&["osv", "queries", &format!("{name}.json")])
    }

    /// Every record: cached while its `modified` stamp is the one OSV gave (any offline), fetched otherwise.
    fn records(&self, ids: &[(&str, Option<&str>)]) -> Result<Vec<Record>, String> {
        let chunk = ids.len().div_ceil(WORKERS).max(1);
        std::thread::scope(|scope| {
            let workers: Vec<_> = ids
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        part.iter()
                            .map(|(id, modified)| self.record(id, *modified))
                            .collect::<Result<Vec<_>, _>>()
                    })
                })
                .collect();
            let mut out = Vec::new();
            for worker in workers {
                out.extend(worker.join().expect("a record fetch does not panic")?);
            }
            Ok(out)
        })
    }

    fn record(&self, id: &str, modified: Option<&str>) -> Result<Record, String> {
        let file = self.file(&["osv", "vulns", &format!("{id}.json")]);
        let cached = file
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str::<Record>(&text).ok());
        if let Some(record) = cached {
            let current = match (modified, record.modified.as_deref()) {
                (Some(wanted), Some(have)) => same_instant(wanted, have),
                (None, _) => true,
                (Some(_), None) => false,
            };
            if self.offline || current {
                return Ok(record);
            }
        }
        if self.offline {
            return Err(self.offline_error(&format!("OSV's record {id}")));
        }
        let url = format!("{}/v1/vulns/{id}", self.endpoints.osv.trim_end_matches('/'));
        let text = self
            .client
            .get(&url)
            .map_err(|err| format!("cannot fetch OSV's record {id} from {url}: {err}"))?;
        let record: Record = serde_json::from_str(&text)
            .map_err(|err| format!("OSV's record {id} from {url} is not a record: {err}"))?;
        if let Some(path) = &file {
            keep(path, &text);
        }
        Ok(record)
    }

    /// The CVE ids in CISA's catalog.
    fn kev(&self) -> Result<HashSet<String>, String> {
        #[derive(Deserialize)]
        struct Catalog {
            #[serde(default)]
            vulnerabilities: Vec<Entry>,
        }
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "cveID")]
            cve: String,
        }
        let text = self.daily("kev.json", &self.endpoints.kev, "CISA's KEV catalog")?;
        let catalog: Catalog = serde_json::from_str(&text).map_err(|err| format!("CISA's KEV catalog: {err}"))?;
        if catalog.vulnerabilities.is_empty() {
            return Err(format!("CISA's KEV catalog from {} is empty", self.endpoints.kev));
        }
        Ok(catalog
            .vulnerabilities
            .into_iter()
            .map(|entry| entry.cve.to_ascii_uppercase())
            .collect())
    }

    /// The EPSS score of each of `cves` FIRST has scored: cached scores younger than a day (any age offline), the
    /// rest asked for in batches; a failed batch falls back to stale scores when every CVE in it has one.
    fn epss(&self, cves: &BTreeSet<String>) -> Result<HashMap<String, f64>, String> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct Entry {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            epss: Option<f64>,
            fetched: u64,
        }
        #[derive(Deserialize)]
        struct Answer {
            #[serde(default)]
            data: Vec<Row>,
        }
        #[derive(Deserialize)]
        struct Row {
            cve: String,
            epss: serde_json::Value,
        }
        let file = self.file(&["epss.json"]);
        let mut cache: BTreeMap<String, Entry> = file
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let now = seconds(self.now);
        let fresh = |entry: &Entry| self.offline || now.saturating_sub(entry.fetched) <= DAY.as_secs();
        let missing: Vec<&String> = cves.iter().filter(|cve| !cache.get(*cve).is_some_and(fresh)).collect();
        if self.offline && !missing.is_empty() {
            return Err(self.offline_error(&format!("the EPSS score of {}", missing[0])));
        }
        let mut asked = false;
        for batch in missing.chunks(EPSS_BATCH) {
            let names: Vec<&str> = batch.iter().map(|cve| cve.as_str()).collect();
            let url = format!("{}?cve={}", self.endpoints.epss, names.join(","));
            match self.client.get(&url) {
                Ok(text) => {
                    let answer: Answer = serde_json::from_str(&text).map_err(|err| {
                        format!(
                            "FIRST's EPSS API at {} answered with something else: {err}",
                            self.endpoints.epss
                        )
                    })?;
                    let mut rows: HashMap<String, f64> = answer
                        .data
                        .into_iter()
                        .filter_map(|row| {
                            let score = match row.epss {
                                serde_json::Value::Number(n) => n.as_f64(),
                                serde_json::Value::String(s) => s.trim().parse().ok(),
                                _ => None,
                            };
                            Some((row.cve.to_ascii_uppercase(), score?))
                        })
                        .collect();
                    // A CVE FIRST has not scored is cached too, so it is not asked about again until tomorrow.
                    for cve in batch {
                        cache.insert(
                            (*cve).clone(),
                            Entry {
                                epss: rows.remove(*cve),
                                fetched: now,
                            },
                        );
                    }
                    asked = true;
                }
                Err(err) if batch.iter().all(|cve| cache.contains_key(*cve)) => {
                    tracing::warn!(%err, "EPSS request failed; using the stale cached scores");
                }
                Err(err) => {
                    return Err(format!("cannot ask FIRST's EPSS API at {}: {err}", self.endpoints.epss));
                }
            }
        }
        if asked && let Some(path) = &file {
            keep(path, &serde_json::to_string(&cache).expect("the scores are JSON"));
        }
        Ok(cves
            .iter()
            .filter_map(|cve| Some((cve.clone(), cache.get(cve)?.epss?)))
            .collect())
    }
}

/// Merge the records that describe the same vulnerability (they share an id or alias) into one advisory each, led by
/// the best-described record. Also each record's advisory, by position.
fn merge(records: &[Record]) -> (Vec<Advisory>, Vec<usize>) {
    fn root(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut parent: Vec<usize> = (0..records.len()).collect();
    let mut owner: HashMap<&str, usize> = HashMap::new();
    for (i, record) in records.iter().enumerate() {
        for name in std::iter::once(&record.id).chain(&record.aliases) {
            match owner.get(name.as_str()) {
                Some(&j) => {
                    let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                    parent[a] = b;
                }
                None => {
                    owner.insert(name, i);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..records.len() {
        let r = root(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }
    let mut advisories = Vec::new();
    let mut belongs = vec![0; records.len()];
    for members in groups.into_values() {
        let lead = *members
            .iter()
            .max_by_key(|&&i| {
                let record = &records[i];
                let (level, scored) = record.level();
                (
                    scored,
                    level != Level::Unknown,
                    record.summary.is_some(),
                    record.id.starts_with("GHSA-"),
                    std::cmp::Reverse(record.id.clone()),
                )
            })
            .expect("a group has a member");
        let id = records[lead].id.clone();
        let aliases: BTreeSet<String> = members
            .iter()
            .flat_map(|&i| std::iter::once(&records[i].id).chain(&records[i].aliases))
            .filter(|name| **name != id)
            .cloned()
            .collect();
        let summary = std::iter::once(lead)
            .chain(members.iter().copied())
            .find_map(|i| records[i].summary.clone().filter(|s| !s.trim().is_empty()));
        let level = members
            .iter()
            .map(|&i| records[i].level().0)
            .max()
            .unwrap_or(Level::Unknown);
        for &i in &members {
            belongs[i] = advisories.len();
        }
        advisories.push(Advisory {
            id,
            aliases: aliases.into_iter().collect(),
            summary,
            level,
            known_exploited: false,
            epss: None,
        });
    }
    (advisories, belongs)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Answers from a table of URL to text, and counts the requests.
    #[derive(Default)]
    pub struct Recorded {
        pub answers: Vec<(String, String)>,
        pub asked: Mutex<Vec<String>>,
    }

    impl Recorded {
        fn answer(&self, url: &str) -> Result<String, String> {
            self.asked.lock().unwrap().push(url.to_string());
            self.answers
                .iter()
                .find(|(prefix, _)| url.starts_with(prefix.as_str()))
                .map(|(_, text)| text.clone())
                .ok_or_else(|| format!("no answer for {url}"))
        }
    }

    impl Client for Recorded {
        fn get(&self, url: &str) -> Result<String, String> {
            self.answer(url)
        }
        fn post(&self, url: &str, _body: &str) -> Result<String, String> {
            self.answer(url)
        }
    }

    const BATCH: &str = r#"{"results":[{"vulns":[{"id":"GHSA-1","modified":"2026-01-02T03:04:05.123456Z"},
        {"id":"PYSEC-1","modified":"2026-01-02T03:04:05Z"}]}]}"#;
    const GHSA: &str = r#"{"id":"GHSA-1","aliases":["CVE-2026-1"],"summary":"bad","modified":"2026-01-02T03:04:05.123456789Z",
        "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "affected":[{"package":{"purl":"pkg:pypi/demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.5"},{"fixed":"2.1"}]}]}],
        "database_specific":{"severity":"MODERATE"}}"#;
    const PYSEC: &str =
        r#"{"id":"PYSEC-1","aliases":["CVE-2026-1"],"modified":"2026-01-02T03:04:05Z","severity":null}"#;
    const KEV: &str = r#"{"vulnerabilities":[{"cveID":"cve-2026-1"}]}"#;
    const EPSS: &str = r#"{"data":[{"cve":"CVE-2026-1","epss":"0.42","percentile":"0.9"}]}"#;

    fn recorded() -> Recorded {
        Recorded {
            answers: vec![
                (format!("{OSV_URL}/v1/querybatch"), BATCH.into()),
                (format!("{OSV_URL}/v1/vulns/GHSA-1"), GHSA.into()),
                (format!("{OSV_URL}/v1/vulns/PYSEC-1"), PYSEC.into()),
                (KEV_URL.into(), KEV.into()),
                (EPSS_URL.into(), EPSS.into()),
            ],
            ..Recorded::default()
        }
    }

    fn lookup<'a>(client: &'a dyn Client, cache: &'a Path, offline: bool, endpoints: &'a Endpoints) -> Lookup<'a> {
        Lookup {
            endpoints,
            cache: Some(cache),
            offline,
            client,
            now: SystemTime::now(),
        }
    }

    fn purls() -> BTreeSet<String> {
        BTreeSet::from(["pkg:pypi/demo@2.0".to_string()])
    }

    #[test]
    fn records_sharing_a_cve_are_one_advisory_with_the_worst_level_kev_and_epss() {
        let cache = tempfile::tempdir().unwrap();
        let client = recorded();
        let endpoints = Endpoints::default();
        let data = lookup(&client, cache.path(), false, &endpoints)
            .run(&purls(), Wanted { kev: true, epss: true })
            .unwrap();
        assert_eq!(data.advisories.len(), 1);
        let advisory = &data.advisories[0];
        assert_eq!(advisory.id, "GHSA-1");
        assert_eq!(advisory.aliases, ["CVE-2026-1", "PYSEC-1"]);
        assert_eq!(advisory.summary.as_deref(), Some("bad"));
        // MODERATE from the database, 7.5 from the vector: the worse wins.
        assert_eq!(advisory.level, Level::High);
        assert!(advisory.known_exploited);
        assert_eq!(advisory.epss, Some(0.42));
        assert_eq!(advisory.url(), "https://osv.dev/vulnerability/GHSA-1");
        assert_eq!(data.by_purl["pkg:pypi/demo@2.0"][0].fixed.as_deref(), Some("2.1"));

        // Everything is cached now: offline, the same answer without a request.
        let none = Recorded::default();
        let again = lookup(&none, cache.path(), true, &endpoints)
            .run(&purls(), Wanted { kev: true, epss: true })
            .unwrap();
        assert_eq!(again.advisories, data.advisories);
        assert!(none.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn offline_without_a_cached_copy_is_an_error() {
        let cache = tempfile::tempdir().unwrap();
        let none = Recorded::default();
        let endpoints = Endpoints::default();
        let err = lookup(&none, cache.path(), true, &endpoints)
            .run(&purls(), Wanted::default())
            .unwrap_err();
        assert!(err.contains("PIXI_POLICY_OFFLINE"), "{err}");
        assert!(lookup(&none, cache.path(), true, &endpoints).mapping().is_err());
    }

    #[test]
    fn a_failed_request_with_nothing_cached_is_an_error() {
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let none = Recorded::default();
        let err = lookup(&none, cache.path(), false, &endpoints)
            .run(&purls(), Wanted::default())
            .unwrap_err();
        assert!(err.starts_with("cannot query OSV"), "{err}");
        let mut no_record = recorded();
        no_record.answers.retain(|(url, _)| !url.ends_with("PYSEC-1"));
        let err = lookup(&no_record, cache.path(), false, &endpoints)
            .run(&purls(), Wanted::default())
            .unwrap_err();
        assert!(err.contains("cannot fetch OSV's record PYSEC-1"), "{err}");
        let mut no_kev = recorded();
        no_kev.answers.retain(|(url, _)| url != KEV_URL);
        let err = lookup(&no_kev, cache.path(), false, &endpoints)
            .run(&purls(), Wanted { kev: true, epss: false })
            .unwrap_err();
        assert!(err.contains("CISA's KEV catalog"), "{err}");
        let mut no_epss = recorded();
        no_epss.answers.retain(|(url, _)| url != EPSS_URL);
        let err = lookup(&no_epss, cache.path(), false, &endpoints)
            .run(&purls(), Wanted { kev: false, epss: true })
            .unwrap_err();
        assert!(err.contains("EPSS"), "{err}");
    }

    #[test]
    fn a_stale_copy_stands_in_when_the_download_fails() {
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let client = recorded();
        let fresh = lookup(&client, cache.path(), false, &endpoints);
        fresh.run(&purls(), Wanted { kev: true, epss: true }).unwrap();
        let mut later = lookup(&client, cache.path(), false, &endpoints);
        later.now = SystemTime::now() + 2 * DAY;
        let mut down = recorded();
        down.answers.retain(|(url, _)| url != KEV_URL && url != EPSS_URL);
        later.client = &down;
        let data = later.run(&purls(), Wanted { kev: true, epss: true }).unwrap();
        assert!(data.advisories[0].known_exploited);
        assert_eq!(data.advisories[0].epss, Some(0.42));
    }

    #[test]
    fn an_empty_kev_catalog_is_an_error() {
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let mut client = recorded();
        client.answers.retain(|(url, _)| url != KEV_URL);
        client
            .answers
            .push((KEV_URL.into(), r#"{"vulnerabilities":[]}"#.into()));
        let err = lookup(&client, cache.path(), false, &endpoints)
            .run(&purls(), Wanted { kev: true, epss: false })
            .unwrap_err();
        assert!(err.contains("is empty"), "{err}");
    }

    #[test]
    fn levels_come_from_words_and_scores() {
        assert_eq!(Level::parse("Moderate"), Some(Level::Medium));
        assert_eq!(Level::parse("severe"), None);
        assert_eq!(
            [0.0, 3.9, 4.0, 7.0, 9.0].map(Level::from_score),
            [Level::None, Level::Low, Level::Medium, Level::High, Level::Critical]
        );
        assert_eq!(
            [Level::Unknown, Level::None, Level::Low, Level::Medium, Level::Critical].map(Level::name),
            ["unknown", "none", "low", "medium", "critical"]
        );
        let record: Record = serde_json::from_str(PYSEC).unwrap();
        assert_eq!(record.level(), (Level::Unknown, false));
    }

    #[test]
    fn same_instant_ignores_precision_beyond_microseconds() {
        assert!(same_instant(
            "2026-01-02T03:04:05.123456Z",
            "2026-01-02T03:04:05.123456789Z"
        ));
        assert!(same_instant("2026-01-02T03:04:05Z", "2026-01-02T03:04:05.000000Z"));
        assert!(!same_instant("2026-01-02T03:04:05.1Z", "2026-01-02T03:04:05.2Z"));
    }

    #[test]
    fn the_fixed_version_is_the_smallest_above_the_installed_one() {
        let record: Record = serde_json::from_str(GHSA).unwrap();
        assert_eq!(record.fixed("pkg:pypi/demo@1.0").as_deref(), Some("1.5"));
        assert_eq!(record.fixed("pkg:pypi/demo@9").as_deref(), Some("2.1"));
        assert_eq!(record.fixed("pkg:pypi/other@1.0"), None);
    }

    #[test]
    fn the_mapping_takes_a_name_a_list_or_null() {
        let mapping = Mapping::parse(r#"{"Jinja2":"jinja2","pyyaml":["PyYAML"],"libzlib":null}"#).unwrap();
        assert_eq!(mapping.0["jinja2"], ["jinja2"]);
        assert_eq!(mapping.0["pyyaml"], ["PyYAML"]);
        assert!(mapping.0["libzlib"].is_empty());
        assert!(Mapping::parse("[]").is_err());
    }

    #[test]
    fn mirrors_come_from_the_environment() {
        let endpoints = Endpoints::from_env();
        if std::env::var_os("PIXI_POLICY_OSV_URL").is_none() {
            assert_eq!(endpoints.osv, OSV_URL);
        }
    }
}
