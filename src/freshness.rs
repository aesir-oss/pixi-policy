//! The channel data `[freshness]` checks against (#2): each conda package's newest release, from the repodata of the
//! channel and subdir its pixi.lock entry names, so a package is judged against the channel it is installed from
//! (conda.anaconda.org, prefix.dev or a mirror); and whether conda-forge has archived its feedstock, from the
//! conda-forge bot's feedstock list (decided on #2).
//!
//! Repodata is read sharded (CEP-16) where the channel serves it: the shard index, then one small shard per package.
//! A channel without shards is read whole, from `repodata.json.zst` or `repodata.json`, and only the newest version of
//! each name is kept. The index, the reduced repodata and the feedstock lists are cached for a day, shards for good
//! (they are named by their hash). Offline, a cached copy of any age stands in, and a failed download falls back to a
//! stale copy; with no copy at all the lookup fails, and the check with it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rattler_conda_types::Version;
use rattler_conda_types::{Shard, ShardedRepodata};
use serde::Deserialize;

pub const FEEDSTOCKS_URL: &str =
    "https://raw.githubusercontent.com/regro/cf-graph-countyfair/master/all_feedstocks.json";
pub const OUTPUTS_URL: &str =
    "https://raw.githubusercontent.com/conda-forge/feedstock-outputs/single-file/feedstock-outputs.json";

/// PyPI, whose JSON API gives each project's releases, files, upload times and yanked releases (#52).
pub const PYPI_URL: &str = "https://pypi.org";

/// How long an index, reduced repodata or a feedstock list is trusted: channels and the bot publish many times a day,
/// and a release a day late is still caught tomorrow.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest file read, in bytes: a whole channel's repodata, compressed.
const MAX_BYTES: u64 = 512 << 20;
/// The largest a decompressed file may be.
const MAX_DECOMPRESSED: u64 = 4 << 30;

/// Where the feedstock lists come from: conda-forge's, or the mirrors `PIXI_POLICY_FEEDSTOCKS_URL` and
/// `PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL` name. Repodata comes from each package's own channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub feedstocks: String,
    pub outputs: String,
    /// PyPI's JSON API (#52).
    pub pypi: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            feedstocks: FEEDSTOCKS_URL.into(),
            outputs: OUTPUTS_URL.into(),
            pypi: PYPI_URL.into(),
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
            feedstocks: var("PIXI_POLICY_FEEDSTOCKS_URL", FEEDSTOCKS_URL),
            outputs: var("PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL", OUTPUTS_URL),
            pypi: var("PIXI_POLICY_PYPI_URL", PYPI_URL),
        }
    }
}

/// What a lookup needs from the network, so tests can answer for it. `None` is a file the server does not have.
pub trait Client: Sync {
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String>;
}

/// The network.
pub struct Http;

impl Client for Http {
    fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
        crate::fetch::get_if_served(url, MAX_BYTES)
    }
}

/// A package in a channel: the channel's URL, the subdir and the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub channel: String,
    pub subdir: String,
    pub name: String,
}

/// The newest release of each package looked up; `None` for one its channel does not list.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Releases(pub(crate) HashMap<Key, Option<String>>);

impl Releases {
    /// The newest release of `key` in its subdir or in noarch, since a package can move between them (setuptools'
    /// linux-64 builds stop at 65): `None` when it was not looked up, `Some(None)` when neither lists it.
    pub fn newest(&self, key: &Key) -> Option<Option<String>> {
        let noarch = Key {
            subdir: "noarch".into(),
            ..key.clone()
        };
        let found: Vec<&Option<String>> = [key, &noarch].into_iter().filter_map(|k| self.0.get(k)).collect();
        if found.is_empty() {
            return None;
        }
        Some(newest(found.into_iter().flatten().map(String::as_str)))
    }

    /// The keys to look up for `key`: its own, and noarch's.
    pub fn wanted(key: Key) -> [Key; 2] {
        let noarch = Key {
            subdir: "noarch".into(),
            ..key.clone()
        };
        [key, noarch]
    }
}

/// conda-forge's feedstocks: which feedstocks build each package, and which feedstocks are archived.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Feedstocks {
    outputs: HashMap<String, Vec<String>>,
    archived: HashSet<String>,
}

/// What the feedstock list says about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feedstock {
    /// Every feedstock that builds it is archived; their names.
    Archived(Vec<String>),
    /// A feedstock that builds it is active.
    Active,
    /// No feedstock is known to build it.
    Unknown,
}

impl Feedstocks {
    pub fn parse(feedstocks: &str, outputs: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct List {
            #[serde(default)]
            archived: Vec<String>,
            #[serde(default)]
            active: Vec<String>,
        }
        let list: List = serde_json::from_str(feedstocks)
            .map_err(|err| format!("conda-forge's feedstock list is not JSON: {err}"))?;
        if list.active.is_empty() {
            return Err("conda-forge's feedstock list names no active feedstock".into());
        }
        let outputs: HashMap<String, Vec<String>> = serde_json::from_str(outputs)
            .map_err(|err| format!("conda-forge's feedstock outputs are not JSON: {err}"))?;
        Ok(Self {
            outputs,
            archived: list.archived.into_iter().collect(),
        })
    }

    /// Whether the feedstocks that build `package` are archived. A package more than one feedstock builds counts as
    /// archived only when all of them are, since the lockfile does not say which one built it.
    pub fn of(&self, package: &str) -> Feedstock {
        match self.outputs.get(package) {
            None => Feedstock::Unknown,
            Some(feedstocks) if feedstocks.is_empty() => Feedstock::Unknown,
            Some(feedstocks) if feedstocks.iter().all(|f| self.archived.contains(f)) => {
                Feedstock::Archived(feedstocks.clone())
            }
            Some(_) => Feedstock::Active,
        }
    }
}

/// Whether a version names a prerelease (`2.0.0rc1`, `1.4.0b2`, `0.9.dev3`). From pixi-sbom's outdated report.
pub fn is_prerelease(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for marker in ["rc", "alpha", "beta", "dev", "pre", "a", "b"] {
        let mut from = 0;
        while let Some(at) = lower[from..].find(marker) {
            let at = from + at;
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + marker.len()).copied();
            // A marker counts only between a digit (or separator) and a digit or the end: `2.0.0rc1` and `1.0b` do,
            // `alpine` and `libarrow` do not.
            let starts = before.is_none_or(|b| b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_');
            let ends = after.is_none_or(|b| b.is_ascii_digit());
            if starts && ends && at > 0 {
                return true;
            }
            from = at + 1;
        }
    }
    false
}

/// The major version: the leading number, after any epoch (`1!2.0` is 2).
pub fn major(version: &str) -> Option<u64> {
    let version = version.split_once('!').map_or(version, |(_, rest)| rest);
    let digits: String = version.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The newest of `versions`, leaving prereleases out unless there is nothing else.
pub fn newest<'a>(versions: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let parsed: Vec<(Version, &str)> = versions
        .into_iter()
        .filter_map(|v| v.parse::<Version>().ok().map(|parsed| (parsed, v)))
        .collect();
    let stable = parsed
        .iter()
        .filter(|(_, v)| !is_prerelease(v))
        .max_by(|a, b| a.0.cmp(&b.0));
    stable
        .or_else(|| parsed.iter().max_by(|a, b| a.0.cmp(&b.0)))
        .map(|(_, v)| (*v).to_string())
}

/// `bytes` decompressed when they are zstd, as they are when the name ends in `.zst`.
fn unzstd(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(bytes).map_err(|err| format!("not zstd: {err}"))?;
    let mut out = Vec::new();
    (&mut decoder)
        .take(MAX_DECOMPRESSED)
        .read_to_end(&mut out)
        .map_err(|err| format!("cannot decompress: {err}"))?;
    Ok(out)
}

/// One lookup: the cache, whether the network may be used, and the clock.
pub struct Lookup<'a> {
    pub endpoints: &'a Endpoints,
    pub cache: Option<&'a Path>,
    pub offline: bool,
    pub client: &'a dyn Client,
    pub now: SystemTime,
}

/// One PyPI project, reduced: its newest release and when each of its files was uploaded.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Project {
    /// The newest release that is not a prerelease and not yanked; a prerelease when there is nothing else.
    pub newest: Option<String>,
    /// Each file's upload time, in seconds since 1970, by its sha256.
    pub uploads: HashMap<String, i64>,
}

impl Project {
    /// From PyPI's JSON API (`/pypi/<name>/json`).
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Digests {
            sha256: Option<String>,
        }
        #[derive(Deserialize)]
        struct File {
            digests: Digests,
            upload_time_iso_8601: Option<String>,
            #[serde(default)]
            yanked: bool,
        }
        #[derive(Deserialize)]
        struct Api {
            #[serde(default)]
            releases: HashMap<String, Vec<File>>,
        }
        let api: Api = serde_json::from_slice(bytes).map_err(|err| err.to_string())?;
        let mut uploads = HashMap::new();
        let mut live = Vec::new();
        for (version, files) in &api.releases {
            for file in files {
                if let (Some(sha), Some(time)) = (&file.digests.sha256, file.upload_time_iso_8601.as_deref())
                    && let Some(seconds) = seconds(time)
                {
                    uploads.insert(sha.clone(), seconds);
                }
            }
            if !files.is_empty() && files.iter().any(|file| !file.yanked) {
                live.push(version.as_str());
            }
        }
        Ok(Self {
            newest: newest_pypi(live),
            uploads,
        })
    }
}

/// `2024-03-05T12:34:56.123456Z` in seconds since 1970.
fn seconds(time: &str) -> Option<i64> {
    let mut ymd = time.get(..10)?.split('-').map(|part| part.parse::<u32>().ok());
    let (year, month, day) = (ymd.next()??, ymd.next()??, ymd.next()??);
    let date = crate::waivers::Date {
        year: i32::try_from(year).ok()?,
        month,
        day,
    };
    let clock = time.get(11..19)?;
    let mut parts = clock.split(':').map(|part| part.parse::<i64>().ok());
    let (h, m, s) = (parts.next()??, parts.next()??, parts.next()??);
    Some(date.days() * 86_400 + h * 3600 + m * 60 + s)
}

/// The newest of PyPI `versions` by PEP 440, leaving prereleases out unless there is nothing else.
fn newest_pypi<'a>(versions: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let parsed: Vec<(pep440_rs::Version, &str)> = versions
        .into_iter()
        .filter_map(|v| v.parse::<pep440_rs::Version>().ok().map(|parsed| (parsed, v)))
        .collect();
    parsed
        .iter()
        .filter(|(version, _)| !version.any_prerelease())
        .max_by(|a, b| a.0.cmp(&b.0))
        .or_else(|| parsed.iter().max_by(|a, b| a.0.cmp(&b.0)))
        .map(|(_, v)| (*v).to_string())
}

/// What PyPI says about each project looked up, by normalized name.
#[derive(Debug, Default)]
pub struct PypiReleases(pub(crate) HashMap<String, Project>);

impl PypiReleases {
    /// The project `name` (normalized), when PyPI has it.
    pub fn project(&self, name: &str) -> Option<&Project> {
        self.0.get(name)
    }
}

/// Write a cache file; a cache that cannot be written only costs the next run a fetch.
fn keep(path: &Path, bytes: &[u8]) {
    if let Err(err) = crate::fetch::store(path, bytes) {
        tracing::debug!(path = %path.display(), %err, "cannot cache");
    }
}

impl Lookup<'_> {
    fn file(&self, parts: &[&str]) -> Option<PathBuf> {
        self.cache
            .map(|dir| parts.iter().fold(dir.join("freshness"), |path, part| path.join(part)))
    }

    fn offline_error(&self, what: &str) -> String {
        format!("{what} is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it")
    }

    /// A copy kept for `max_age` (any age offline), else a fresh one, else the stale copy. `Ok(None)` when the server
    /// has no such file.
    fn cached(
        &self,
        file: Option<PathBuf>,
        url: &str,
        max_age: Duration,
        what: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let cached = file.as_deref().and_then(|path| std::fs::read(path).ok());
        let age = file
            .as_deref()
            .and_then(|path| std::fs::metadata(path).and_then(|meta| meta.modified()).ok())
            .map(|modified| self.now.duration_since(modified).unwrap_or(Duration::ZERO));
        if let (Some(bytes), Some(age)) = (&cached, age)
            && (self.offline || age <= max_age)
        {
            return Ok(Some(bytes.clone()));
        }
        if self.offline {
            return Err(self.offline_error(what));
        }
        match self.client.get(url) {
            Ok(Some(bytes)) => {
                if let Some(path) = &file {
                    keep(path, &bytes);
                }
                Ok(Some(bytes))
            }
            Ok(None) => Ok(None),
            Err(err) => match cached {
                Some(bytes) => {
                    tracing::warn!(url, %err, "download failed; using the stale cached copy");
                    Ok(Some(bytes))
                }
                None => Err(format!("cannot download {what} from {url}: {err}")),
            },
        }
    }

    /// conda-forge's feedstock list and which feedstocks build each package.
    pub fn feedstocks(&self) -> Result<Feedstocks, String> {
        let get = |name: &str, url: &str, what: &str| {
            self.cached(self.file(&[name]), url, DAY, what)?
                .ok_or_else(|| format!("{url} does not serve {what}"))
                .and_then(|bytes| String::from_utf8(bytes).map_err(|_| format!("{what} is not UTF-8 text")))
        };
        let feedstocks = get(
            "feedstocks.json",
            &self.endpoints.feedstocks,
            "conda-forge's feedstock list",
        )?;
        let outputs = get(
            "feedstock-outputs.json",
            &self.endpoints.outputs,
            "conda-forge's feedstock outputs",
        )?;
        Feedstocks::parse(&feedstocks, &outputs)
    }

    /// What PyPI says about each of `names` (normalized), a few at a time; a project PyPI does not have is left out.
    pub fn pypi(&self, names: &BTreeSet<String>) -> Result<PypiReleases, String> {
        let names: Vec<&String> = names.iter().collect();
        let workers = 8.min(names.len().max(1));
        let chunk = names.len().div_ceil(workers).max(1);
        let results: Vec<Result<Option<(String, Project)>, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = names
                .chunks(chunk)
                .map(|part| scope.spawn(move || part.iter().map(|name| self.project(name)).collect::<Vec<_>>()))
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("a lookup thread does not panic"))
                .collect()
        });
        let mut out = HashMap::new();
        for result in results {
            if let Some((name, project)) = result? {
                out.insert(name, project);
            }
        }
        Ok(PypiReleases(out))
    }

    /// One project's newest release and upload times, kept reduced to that.
    fn project(&self, name: &str) -> Result<Option<(String, Project)>, String> {
        let file = self.file(&["pypi", &format!("{name}.json")]);
        let fresh = |path: &Path| {
            let age = std::fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
            (self.offline || self.now.duration_since(age).unwrap_or(Duration::ZERO) <= DAY)
                .then(|| std::fs::read(path).ok())
                .flatten()
        };
        if let Some(bytes) = file.as_deref().and_then(fresh)
            && let Ok(project) = serde_json::from_slice::<Project>(&bytes)
        {
            return Ok(Some((name.to_string(), project)));
        }
        let what = format!("PyPI's release data for {name}");
        if self.offline {
            return Err(self.offline_error(&what));
        }
        let url = format!("{}/pypi/{name}/json", self.endpoints.pypi.trim_end_matches('/'));
        let Some(bytes) = self
            .client
            .get(&url)
            .map_err(|err| format!("cannot download {what} from {url}: {err}"))?
        else {
            return Ok(None);
        };
        let project = Project::from_json(&bytes).map_err(|err| format!("{url} is not PyPI's JSON API: {err}"))?;
        if let Some(path) = &file {
            keep(path, &serde_json::to_vec(&project).expect("a project serializes"));
        }
        Ok(Some((name.to_string(), project)))
    }

    /// The newest release of every key, channel and subdir at a time.
    pub fn releases(&self, keys: &BTreeSet<Key>) -> Result<Releases, String> {
        let mut by_subdir: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
        for key in keys {
            by_subdir
                .entry((&key.channel, &key.subdir))
                .or_default()
                .push(&key.name);
        }
        let mut out = HashMap::new();
        for ((channel, subdir), names) in by_subdir {
            for (name, newest) in self.subdir(channel, subdir, &names)? {
                out.insert(
                    Key {
                        channel: channel.to_string(),
                        subdir: subdir.to_string(),
                        name,
                    },
                    newest,
                );
            }
        }
        Ok(Releases(out))
    }

    /// The newest release of each of `names` in one channel's subdir.
    fn subdir(&self, channel: &str, subdir: &str, names: &[&str]) -> Result<Vec<(String, Option<String>)>, String> {
        let base = format!("{}/{subdir}/", channel.trim_end_matches('/'));
        let place = format!(
            "{}-{subdir}",
            &crate::fetch::sha256(channel.trim_end_matches('/').as_bytes())[..16]
        );
        let index_url = format!("{base}repodata_shards.msgpack.zst");
        let what = format!("the repodata of {channel} {subdir}");
        let index_file = self.file(&["repodata", &place, "repodata_shards.msgpack.zst"]);
        // Offline with no index cached, the channel may be one that serves no shards: its reduced repodata answers.
        let unsharded = self.offline && !index_file.as_deref().is_some_and(Path::exists);
        let index = match unsharded {
            true => None,
            false => self.cached(index_file, &index_url, DAY, &what)?,
        };
        let Some(index) = index else {
            let newest = self.whole(&base, &place, &what)?;
            return Ok(names
                .iter()
                .map(|name| (name.to_string(), newest.get(*name).cloned()))
                .collect());
        };
        let index: ShardedRepodata = rmp_serde::from_slice(&unzstd(&index)?)
            .map_err(|err| format!("{index_url} is not a shard index: {err}"))?;
        let shards = join(&index_url, &index.info.shards_base_url);
        let mut out = Vec::new();
        for name in names {
            let Some(hash) = index.shards.get(*name) else {
                out.push((name.to_string(), None));
                continue;
            };
            let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
            let url = format!("{shards}{hex}.msgpack.zst");
            let bytes = self
                .cached(
                    self.file(&["shards", &format!("{hex}.msgpack.zst")]),
                    &url,
                    Duration::MAX,
                    &format!("the repodata shard of {name} in {channel} {subdir}"),
                )?
                .ok_or_else(|| format!("{url}, the shard of {name} the index names, is missing"))?;
            let shard: Shard = rmp_serde::from_slice(&unzstd(&bytes)?)
                .map_err(|err| format!("{url} is not a repodata shard: {err}"))?;
            let versions: Vec<String> = shard
                .packages
                .values()
                .chain(shard.conda_packages.values())
                .map(|record| record.version.as_str().into_owned())
                .collect();
            out.push((name.to_string(), newest(versions.iter().map(String::as_str))));
        }
        Ok(out)
    }

    /// The newest release of every name in a channel's subdir that serves no shards, from its whole repodata, kept
    /// reduced to that.
    fn whole(&self, base: &str, place: &str, what: &str) -> Result<HashMap<String, String>, String> {
        let reduced = self.file(&["repodata", place, "newest.json"]);
        let cached = reduced.as_deref().and_then(|path| {
            let age = std::fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
            let fresh = self.offline || self.now.duration_since(age).unwrap_or(Duration::ZERO) <= DAY;
            fresh.then(|| std::fs::read(path).ok()).flatten()
        });
        if let Some(bytes) = cached
            && let Ok(newest) = serde_json::from_slice(&bytes)
        {
            return Ok(newest);
        }
        if self.offline {
            return Err(self.offline_error(what));
        }
        #[derive(Deserialize)]
        struct Record {
            name: String,
            version: String,
        }
        #[derive(Deserialize)]
        struct Repodata {
            #[serde(default)]
            packages: HashMap<String, Record>,
            #[serde(default, rename = "packages.conda")]
            conda_packages: HashMap<String, Record>,
        }
        let mut found = None;
        for (file, zstd) in [("repodata.json.zst", true), ("repodata.json", false)] {
            let url = format!("{base}{file}");
            let got = self
                .client
                .get(&url)
                .map_err(|err| format!("cannot download {what} from {url}: {err}"))?;
            if let Some(bytes) = got {
                let bytes = if zstd { unzstd(&bytes)? } else { bytes };
                let repodata: Repodata =
                    serde_json::from_slice(&bytes).map_err(|err| format!("{url} is not repodata: {err}"))?;
                found = Some(repodata);
                break;
            }
        }
        let repodata = found.ok_or_else(|| format!("{base} serves no repodata"))?;
        let mut versions: HashMap<String, Vec<String>> = HashMap::new();
        for record in repodata
            .packages
            .into_values()
            .chain(repodata.conda_packages.into_values())
        {
            versions.entry(record.name).or_default().push(record.version);
        }
        let newest: HashMap<String, String> = versions
            .into_iter()
            .filter_map(|(name, versions)| Some((name, newest(versions.iter().map(String::as_str))?)))
            .collect();
        if let Some(path) = &reduced {
            keep(path, &serde_json::to_vec(&newest).expect("versions are JSON"));
        }
        Ok(newest)
    }
}

/// `relative` read against the URL of the file `base` names: `./shards/` beside
/// `https://host/c/linux-64/repodata_shards.msgpack.zst` is `https://host/c/linux-64/shards/`.
fn join(base: &str, relative: &str) -> String {
    // anaconda.org's index gives an empty base: the shards are beside it.
    let relative = if relative.is_empty() { "./" } else { relative };
    let relative = if relative.ends_with('/') {
        relative.to_string()
    } else {
        format!("{relative}/")
    };
    if relative.contains("://") {
        return relative;
    }
    if let Some(path) = relative.strip_prefix('/') {
        let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
        let host = rest.split('/').next().unwrap_or(rest);
        return format!("{scheme}://{host}/{path}");
    }
    crate::fetch::join(base, &relative).trim_end_matches('/').to_string() + "/"
}

#[cfg(test)]
pub mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn pypis_json_is_reduced_to_the_newest_release_and_the_upload_times() {
        let json = br#"{"releases": {
            "1.0": [{"digests": {"sha256": "a"}, "upload_time_iso_8601": "2020-01-02T03:04:05.123Z"}],
            "2.0": [{"digests": {"sha256": "b"}, "upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": true}],
            "1.5": [{"digests": {"sha256": "c"}, "upload_time_iso_8601": "2020-06-01T00:00:00Z"}],
            "3.0rc1": [{"digests": {"sha256": "d"}, "upload_time_iso_8601": "2022-01-01T00:00:00Z"}],
            "0.1": []
        }}"#;
        let project = Project::from_json(json).unwrap();
        assert_eq!(
            project.newest.as_deref(),
            Some("1.5"),
            "not yanked 2.0, not the prerelease"
        );
        assert_eq!(project.uploads["a"], 18_263 * 86_400 + 3 * 3600 + 4 * 60 + 5);
        assert_eq!(project.uploads.len(), 4);
        assert_eq!(newest_pypi(["1.0rc1", "1.0b2"]).as_deref(), Some("1.0rc1"));
        assert_eq!(seconds("bad"), None);
        assert!(Project::from_json(b"not json").is_err());
    }

    /// Answers from a table of URL to bytes (a missing URL is a 404), and records the requests.
    #[derive(Default)]
    pub struct Recorded {
        pub answers: Vec<(String, Vec<u8>)>,
        pub down: bool,
        /// A directory answering for every shard by its file name.
        pub shards: Option<PathBuf>,
        pub asked: Mutex<Vec<String>>,
    }

    impl Client for Recorded {
        fn get(&self, url: &str) -> Result<Option<Vec<u8>>, String> {
            self.asked.lock().unwrap().push(url.to_string());
            if self.down {
                return Err("connection refused".into());
            }
            if let Some(dir) = &self.shards
                && let Some(name) = url.rsplit('/').next().filter(|n| n.len() == 64 + ".msgpack.zst".len())
            {
                return Ok(std::fs::read(dir.join(name)).ok());
            }
            Ok(self.answers.iter().find(|(u, _)| u == url).map(|(_, b)| b.clone()))
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

    fn zstd(bytes: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(bytes, ruzstd::encoding::CompressionLevel::Fastest)
    }

    const CHANNEL: &str = "https://conda.example.com/forge";

    fn key(name: &str) -> Key {
        Key {
            channel: CHANNEL.into(),
            subdir: "noarch".into(),
            name: name.into(),
        }
    }

    #[test]
    fn whole_repodata_is_read_when_the_channel_serves_no_shards_and_kept_reduced() {
        let repodata = r#"{"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0","build":"0","build_number":0},
            "a-3.0rc1-0.tar.bz2":{"name":"a","version":"3.0rc1","build":"0","build_number":0}},
            "packages.conda":{"a-2.1-0.conda":{"name":"a","version":"2.1","build":"0","build_number":0}}}"#;
        let client = Recorded {
            answers: vec![(format!("{CHANNEL}/noarch/repodata.json.zst"), zstd(repodata.as_bytes()))],
            ..Recorded::default()
        };
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let keys = BTreeSet::from([key("a"), key("b")]);
        let releases = lookup(&client, cache.path(), false, &endpoints)
            .releases(&keys)
            .unwrap();
        assert_eq!(releases.newest(&key("a")), Some(Some("2.1".into())));
        assert_eq!(releases.newest(&key("b")), Some(None));
        assert_eq!(
            releases.newest(&Key {
                name: "c".into(),
                ..key("a")
            }),
            None
        );
        let none = Recorded::default();
        let again = lookup(&none, cache.path(), true, &endpoints).releases(&keys).unwrap();
        assert_eq!(again, releases);
    }

    #[test]
    fn sharded_repodata_is_read_index_then_shard_and_shards_are_kept_for_good() {
        let recorded = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/freshness/cache/freshness");
        let channel = "https://conda.anaconda.org/conda-forge/";
        let place = |subdir: &str| {
            let hash = crate::fetch::sha256(channel.trim_end_matches('/').as_bytes());
            recorded.join(format!("repodata/{}-{subdir}/repodata_shards.msgpack.zst", &hash[..16]))
        };
        let client = Recorded {
            answers: ["linux-64", "noarch"]
                .map(|subdir| {
                    (
                        format!("{channel}{subdir}/repodata_shards.msgpack.zst"),
                        std::fs::read(place(subdir)).unwrap(),
                    )
                })
                .to_vec(),
            shards: Some(recorded.join("shards")),
            ..Recorded::default()
        };
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let setuptools = Key {
            channel: channel.into(),
            subdir: "linux-64".into(),
            name: "setuptools".into(),
        };
        let missing = Key {
            name: "not-a-package".into(),
            ..setuptools.clone()
        };
        let keys: BTreeSet<Key> = [setuptools.clone(), missing.clone()]
            .into_iter()
            .flat_map(Releases::wanted)
            .collect();
        let releases = lookup(&client, cache.path(), false, &endpoints)
            .releases(&keys)
            .unwrap();
        assert_eq!(releases.newest(&setuptools), Some(Some("84.0.0".into())));
        assert_eq!(releases.newest(&missing), Some(None));
        assert!(
            std::fs::read_dir(cache.path().join("freshness/shards"))
                .unwrap()
                .count()
                >= 2
        );
        // A shard the index names but the channel does not serve is an error, not a pass.
        let gone = Recorded {
            answers: client.answers.clone(),
            shards: Some(cache.path().join("nowhere")),
            ..Recorded::default()
        };
        let fresh = tempfile::tempdir().unwrap();
        let err = lookup(&gone, fresh.path(), false, &endpoints)
            .releases(&keys)
            .unwrap_err();
        assert!(err.contains("is missing"), "{err}");
    }

    #[test]
    fn plain_repodata_json_is_the_last_resort_and_none_at_all_is_an_error() {
        let repodata = r#"{"packages":{"a-1.0-0.tar.bz2":{"name":"a","version":"1.0"}}}"#;
        let client = Recorded {
            answers: vec![(format!("{CHANNEL}/noarch/repodata.json"), repodata.as_bytes().to_vec())],
            ..Recorded::default()
        };
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let keys = BTreeSet::from([key("a")]);
        let releases = lookup(&client, cache.path(), false, &endpoints)
            .releases(&keys)
            .unwrap();
        assert_eq!(releases.newest(&key("a")), Some(Some("1.0".into())));
        let empty = tempfile::tempdir().unwrap();
        let err = lookup(&Recorded::default(), empty.path(), false, &endpoints)
            .releases(&keys)
            .unwrap_err();
        assert!(err.ends_with("serves no repodata"), "{err}");
        let err = lookup(&Recorded::default(), empty.path(), true, &endpoints)
            .releases(&keys)
            .unwrap_err();
        assert!(err.contains("PIXI_POLICY_OFFLINE"), "{err}");
        let down = Recorded {
            down: true,
            ..Recorded::default()
        };
        let err = lookup(&down, empty.path(), false, &endpoints)
            .releases(&keys)
            .unwrap_err();
        assert!(err.contains("connection refused"), "{err}");
    }

    #[test]
    fn a_stale_copy_stands_in_when_the_download_fails() {
        let cache = tempfile::tempdir().unwrap();
        let endpoints = Endpoints::default();
        let file = cache.path().join("freshness/feedstocks.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "old").unwrap();
        let down = Recorded {
            down: true,
            ..Recorded::default()
        };
        let mut later = lookup(&down, cache.path(), false, &endpoints);
        later.now = SystemTime::now() + 2 * DAY;
        let got = later
            .cached(Some(file), "https://x/feedstocks.json", DAY, "the list")
            .unwrap();
        assert_eq!(got.as_deref(), Some(&b"old"[..]));
    }

    #[test]
    fn a_package_is_archived_when_every_feedstock_that_builds_it_is() {
        let feedstocks = Feedstocks::parse(
            r#"{"active":["zlib","numpy"],"archived":["zlib-ng","old"]}"#,
            r#"{"libzlib":["zlib","zlib-ng"],"oldpkg":["old"],"numpy":["numpy"],"none":[]}"#,
        )
        .unwrap();
        assert_eq!(feedstocks.of("oldpkg"), Feedstock::Archived(vec!["old".into()]));
        assert_eq!(feedstocks.of("libzlib"), Feedstock::Active);
        assert_eq!(feedstocks.of("numpy"), Feedstock::Active);
        assert_eq!(feedstocks.of("none"), Feedstock::Unknown);
        assert_eq!(feedstocks.of("missing"), Feedstock::Unknown);
        assert!(Feedstocks::parse(r#"{"archived":[]}"#, "{}").is_err());
        assert!(Feedstocks::parse("[", "{}").is_err());
        assert!(Feedstocks::parse(r#"{"active":["a"]}"#, "[").is_err());
    }

    #[test]
    fn versions_compare_as_conda_does_and_prereleases_lose() {
        assert_eq!(newest(["1.10", "1.9", "2.0rc1"]).as_deref(), Some("1.10"));
        assert_eq!(newest(["2.0rc1", "2.0b1"]).as_deref(), Some("2.0rc1"));
        assert_eq!(newest(Vec::<&str>::new()), None);
        assert!(is_prerelease("0.9.dev3") && !is_prerelease("libarrow") && !is_prerelease("1.0"));
        assert_eq!(
            (major("3.1.2"), major("1!2.0"), major("2024a")),
            (Some(3), Some(2), Some(2024))
        );
        assert_eq!(major("abc"), None);
    }

    #[test]
    fn shard_urls_are_read_against_the_index() {
        let index = "https://host/c/linux-64/repodata_shards.msgpack.zst";
        assert_eq!(join(index, "./shards/"), "https://host/c/linux-64/shards/");
        assert_eq!(join(index, ""), "https://host/c/linux-64/");
        assert_eq!(join(index, "https://cdn/x"), "https://cdn/x/");
        assert_eq!(join(index, "/s/c/"), "https://host/s/c/");
    }

    #[test]
    fn mirrors_come_from_the_environment() {
        let endpoints = Endpoints::from_env();
        if std::env::var_os("PIXI_POLICY_FEEDSTOCKS_URL").is_none() {
            assert_eq!(endpoints.feedstocks, FEEDSTOCKS_URL);
        }
    }
}
