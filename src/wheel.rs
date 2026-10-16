//! PyPI licenses (#51): pixi.lock records none, so each locked wheel from pypi.org has its `METADATA` read with HTTP
//! range requests ([`crate::zipread`], ported from pixi-sbom), without downloading the wheel. `License-Expression`
//! (PEP 639) first, then a short `License` field, then a single `License ::` trove classifier; several classifiers are
//! ambiguous. Cached by the wheel's sha256, so a cached answer is never stale and an offline run reads the cache.
//! Sdists, other indexes, URLs, git and paths are not read (decided on #51).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rattler_lock::LockFile;

use crate::fetch::Settings;
use crate::lockfile::{self, Fact, Kind};

/// The host of every pypi.org wheel, which `PIXI_POLICY_WHEEL_URL` replaces with a mirror.
pub const FILES_HOST: &str = "https://files.pythonhosted.org";

/// The `License` field sometimes holds a whole license text; a longer value is not a name.
const MAX_LICENSE_FIELD_LEN: usize = 200;

/// What a wheel's metadata says about its license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A license, as declared (an expression, a `License` field, or a classifier read as SPDX).
    Declared(String),
    /// Several license classifiers, or one that names no single license.
    Ambiguous(String),
    /// The metadata states no license.
    Nothing,
    /// The package was not read, and why.
    NotRead(String),
    /// The metadata could not be read, and why.
    Failed(String),
}

/// The answers for every PyPI package looked up, by sha256 (or location, without one).
#[derive(Debug, Default)]
pub struct Data {
    answers: HashMap<String, Answer>,
}

impl Data {
    /// What the metadata says about `fact`, when it is a PyPI package pixi.lock gives no license for.
    pub fn for_package(&self, fact: &Fact) -> Option<&Answer> {
        (fact.kind == Kind::Pypi)
            .then(|| self.answers.get(&key(fact)))
            .flatten()
    }
}

impl Data {
    /// Record `answer` for the package with sha256 `sha`, as a lookup would.
    pub fn insert(&mut self, sha: &str, answer: Answer) {
        self.answers.insert(sha.to_string(), answer);
    }
}

fn key(fact: &Fact) -> String {
    fact.sha256.clone().unwrap_or_else(|| fact.location.clone())
}

/// Why `fact` is not read, if it is not: only wheels pixi.lock says come from pypi.org are.
fn not_read(fact: &Fact) -> Option<String> {
    if fact.location_is_path || fact.location.starts_with("file:") {
        return Some("it is installed from a local path".into());
    }
    if fact.location.starts_with("git+") {
        return Some("it is built from a git repository".into());
    }
    if fact.sdist || !fact.location.ends_with(".whl") {
        return Some("it is a source distribution, whose license pixi-policy does not read".into());
    }
    match fact.index_host.as_deref() {
        Some("pypi.org") if fact.location.starts_with(FILES_HOST) => None,
        Some(host) => Some(format!(
            "it comes from {host}; pixi-policy reads wheel licenses from pypi.org only"
        )),
        None => Some("it is installed from a URL, not an index".into()),
    }
}

/// `License ::` classifiers that name one SPDX license; the version-less ones (`BSD License`, `Apache Software
/// License`, `GNU General Public License (GPL)`) are left out, as #7 leaves the bare names.
fn classifier(text: &str) -> Option<&'static str> {
    Some(match text {
        "MIT License" => "MIT",
        "MIT No Attribution License (MIT-0)" => "MIT-0",
        "ISC License (ISCL)" => "ISC",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v2 or later (GPLv2+)" => "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU General Public License v3 or later (GPLv3+)" => "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v2 or later (LGPLv2+)" => "LGPL-2.0-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Lesser General Public License v3 or later (LGPLv3+)" => "LGPL-3.0-or-later",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "GNU Affero General Public License v3 or later (AGPLv3+)" => "AGPL-3.0-or-later",
        "Python Software Foundation License" => "PSF-2.0",
        "zlib/libpng License" => "Zlib",
        "The Unlicense (Unlicense)" => "Unlicense",
        "Eclipse Public License 2.0 (EPL-2.0)" => "EPL-2.0",
        "Boost Software License 1.0 (BSL-1.0)" => "BSL-1.0",
        "PostgreSQL License" => "PostgreSQL",
        "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication" => "CC0-1.0",
        _ => return None,
    })
}

/// The headers at the top of `METADATA`, up to the first blank line, names lower-cased, repeats kept in order.
fn headers(metadata: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in metadata.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push('\n');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    out
}

/// What `METADATA` says about the license.
pub fn answer(metadata: &str) -> Answer {
    let headers = headers(metadata);
    let first = |name: &str| {
        headers
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.clone())
    };
    let short = |value: Option<String>| value.filter(|v| v.len() <= MAX_LICENSE_FIELD_LEN && !v.contains('\n'));
    if let Some(expression) = short(first("license-expression")) {
        return Answer::Declared(expression);
    }
    if let Some(license) = short(first("license")).filter(|l| !l.eq_ignore_ascii_case("unknown")) {
        return Answer::Declared(license);
    }
    let classifiers: Vec<&str> = headers
        .iter()
        .filter(|(key, _)| key == "classifier")
        .filter_map(|(_, value)| value.strip_prefix("License :: "))
        .map(|c| c.strip_prefix("OSI Approved :: ").unwrap_or(c))
        .filter(|c| *c != "OSI Approved")
        .collect();
    match classifiers.as_slice() {
        [] => Answer::Nothing,
        [single] => match classifier(single) {
            Some(id) => Answer::Declared(id.into()),
            None => Answer::Ambiguous(format!("the classifier \"License :: {single}\"")),
        },
        many => Answer::Ambiguous(format!("{} license classifiers ({})", many.len(), many.join("; "))),
    }
}

/// Where `fact`'s wheel is read from: its URL, or the mirror `PIXI_POLICY_WHEEL_URL` names.
fn location(fact: &Fact) -> String {
    match std::env::var("PIXI_POLICY_WHEEL_URL").ok().filter(|v| !v.is_empty()) {
        Some(mirror) => format!("{}{}", mirror.trim_end_matches('/'), &fact.location[FILES_HOST.len()..]),
        None => fact.location.clone(),
    }
}

/// The wheel's `METADATA`, from the cache or by range requests.
fn metadata(fact: &Fact, cache: Option<&Path>, offline: bool) -> Result<String, String> {
    let cached: Option<PathBuf> = cache
        .zip(fact.sha256.as_deref())
        .map(|(dir, sha)| dir.join("wheel-info").join(sha).join("METADATA"));
    if let Some(text) = cached.as_deref().and_then(|path| std::fs::read_to_string(path).ok()) {
        return Ok(text);
    }
    if offline {
        return Err("its METADATA is not in the cache, and PIXI_POLICY_OFFLINE forbids fetching it".into());
    }
    let source = crate::zipread::open(&location(fact)).map_err(|err| err.to_string())?;
    let entries = crate::zipread::central_directory(source.as_ref()).map_err(|err| err.to_string())?;
    let entry = entries
        .iter()
        .find(|e| e.name.ends_with(".dist-info/METADATA") && e.name.matches('/').count() == 1)
        .ok_or("the wheel has no dist-info/METADATA")?;
    let bytes = crate::zipread::read_entry(source.as_ref(), entry).map_err(|err| err.to_string())?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if let Some(path) = &cached
        && let Err(err) = crate::fetch::store(path, text.as_bytes())
    {
        tracing::warn!(path = %path.display(), %err, "cannot cache the wheel's METADATA");
    }
    Ok(text)
}

/// Look up every PyPI package of `lock` that pixi.lock gives no license for, a few at a time.
pub fn gather(lock: &LockFile, settings: &Settings) -> Data {
    let mut wanted: HashMap<String, Fact> = HashMap::new();
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment).unwrap_or_default() {
            let Ok(facts) = lockfile::read(lock, &environment, Some(&platform)) else {
                continue;
            };
            for fact in facts.packages {
                if fact.kind == Kind::Pypi && fact.license.is_none() {
                    wanted.entry(key(&fact)).or_insert(fact);
                }
            }
        }
    }
    let mut jobs: Vec<(String, Fact)> = wanted.into_iter().collect();
    jobs.sort_by(|a, b| a.0.cmp(&b.0));
    let look = |fact: &Fact| match not_read(fact) {
        Some(why) => Answer::NotRead(why),
        None => match metadata(fact, settings.cache.as_deref(), settings.offline) {
            Ok(text) => answer(&text),
            Err(why) => Answer::Failed(why),
        },
    };
    let workers = 8.min(jobs.len().max(1));
    let chunk = jobs.len().div_ceil(workers).max(1);
    let answers = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().map(|(k, f)| (k.clone(), look(f))).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("a lookup thread does not panic"))
            .collect()
    });
    Data { answers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expression_wins_then_the_field_then_one_classifier() {
        let meta = |headers: &str| {
            answer(&format!(
                "Metadata-Version: 2.4\nName: x\n{headers}\nBody: not a header\n"
            ))
        };
        assert_eq!(
            meta("License-Expression: MIT\nLicense: BSD\n"),
            Answer::Declared("MIT".into())
        );
        assert_eq!(meta("License: Apache 2.0\n"), Answer::Declared("Apache 2.0".into()));
        assert_eq!(
            meta("License: UNKNOWN\nClassifier: License :: OSI Approved :: MIT License\n"),
            Answer::Declared("MIT".into())
        );
        assert_eq!(
            meta(&format!("License: {}\n", "x".repeat(300))),
            Answer::Nothing,
            "a whole license text is not a name"
        );
        assert_eq!(
            meta("License: line one\n  line two\n"),
            Answer::Nothing,
            "a continued field is a text, not a name"
        );
        assert!(matches!(
            meta("Classifier: License :: OSI Approved :: BSD License\n"),
            Answer::Ambiguous(why) if why.contains("BSD License")
        ));
        assert!(matches!(
            meta("Classifier: License :: OSI Approved :: MIT License\nClassifier: License :: OSI Approved :: Apache Software License\n"),
            Answer::Ambiguous(why) if why.starts_with("2 license classifiers")
        ));
        assert_eq!(meta("Classifier: Programming Language :: Python\n"), Answer::Nothing);
    }

    #[test]
    fn metadata_is_read_from_the_wheel_once_and_from_the_cache_after() {
        let dir = tempfile::tempdir().unwrap();
        let wheel = crate::zipread::tests::zip(
            dir.path(),
            &[
                ("x/__init__.py", b""),
                (
                    "x-1.0.dist-info/METADATA",
                    b"Metadata-Version: 2.4\nName: x\nLicense-Expression: MIT\n",
                ),
            ],
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        let mut fact = lockfile::read(&lock, "default", Some("linux-64"))
            .unwrap()
            .packages
            .remove(0);
        fact.location = wheel.display().to_string();
        fact.sha256 = Some("abc".into());
        let cache = dir.path().join("cache");
        let text = metadata(&fact, Some(&cache), false).unwrap();
        assert_eq!(answer(&text), Answer::Declared("MIT".into()));
        std::fs::remove_file(&wheel).unwrap();
        assert_eq!(
            metadata(&fact, Some(&cache), true).unwrap(),
            text,
            "offline, from the cache"
        );
        fact.sha256 = Some("other".into());
        assert!(
            metadata(&fact, Some(&cache), true)
                .unwrap_err()
                .contains("PIXI_POLICY_OFFLINE")
        );
        let plain = crate::zipread::tests::zip(dir.path(), &[("x/__init__.py", b"")]);
        fact.location = plain.display().to_string();
        assert!(
            metadata(&fact, None, false)
                .unwrap_err()
                .contains("no dist-info/METADATA")
        );
    }

    #[test]
    fn only_pypi_org_wheels_are_read() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        let facts = lockfile::read(&lock, "default", Some("linux-64")).unwrap();
        let why = |name: &str| not_read(facts.packages.iter().find(|f| f.name == name).unwrap());
        assert_eq!(why("requests"), None);
        assert!(why("acme-client").unwrap().contains("pypi.acme.internal"));
        assert!(why("typosquat").unwrap().contains("evil.example") || why("typosquat").unwrap().contains("URL"));
    }
}
