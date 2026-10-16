//! `pixi policy facts` (#9): what pixi-policy knows about a workspace's environments, as JSON a policy engine such as
//! OPA can take as input instead of pixi-policy's own rules. Every environment and platform of pixi.lock, each package
//! with its origin, license and identifiers. The shape is `schemas/pixi-policy-facts.schema.json`, versioned like the
//! report: fields may be added, and a renamed or removed field raises the version.

use std::path::Path;

use rattler_lock::LockFile;
use serde_json::{Value, json};

use crate::check::CheckError;
use crate::license::{self, License};
use crate::lockfile::{self, Fact, Kind};
use crate::rules::sources::{Origin, origin};

/// The facts document's version.
pub const VERSION: u32 = 1;

/// A PyPI purl's distribution name.
fn pypi_name(purl: &str) -> Option<&str> {
    let rest = purl.strip_prefix("pkg:pypi/")?;
    rest.split(['@', '?', '#']).next().filter(|name| !name.is_empty())
}

fn package(fact: &Fact, wheels: Option<&crate::wheel::Data>) -> Value {
    let kind = match fact.kind {
        Kind::CondaBinary => "conda",
        Kind::CondaSource => "conda-source",
        Kind::Pypi => "pypi",
    };
    let (origin_type, url) = match origin(fact) {
        Origin::Channel(url) => ("channel", url),
        Origin::Index(url) => ("index", url),
        Origin::Git(url) => ("git", url),
        Origin::Url(url) => ("url", url),
        Origin::Path(path) => ("path", path),
    };
    let locked = fact.license.as_deref().map(str::trim).filter(|raw| !raw.is_empty());
    let wheel = match wheels.and_then(|data| data.for_package(fact)) {
        Some(crate::wheel::Answer::Declared(raw)) if locked.is_none() => Some(raw.trim()),
        _ => None,
    };
    let raw = locked.or(wheel);
    let source = match (locked, wheel) {
        (Some(_), _) => Some("pixi.lock"),
        (None, Some(_)) => Some("wheel"),
        _ => None,
    };
    let (spdx, status) = match raw.map(license::normalize) {
        None => (None, "missing"),
        Some(License::Expression(expression)) => (Some(expression), "spdx"),
        Some(License::Text(_)) => (None, "text"),
        Some(License::Ambiguous(_)) => (None, "ambiguous"),
    };
    let pypi: Vec<&str> = fact.stated_purls.iter().filter_map(|purl| pypi_name(purl)).collect();
    json!({
        "name": fact.name,
        "version": fact.version,
        "kind": kind,
        "purl": fact.purl,
        "provides_pypi": pypi,
        "origin": {
            "type": origin_type,
            "url": url,
            "channel": fact.channel,
        },
        "license": { "declared": raw, "source": source, "spdx": spdx, "status": status },
        "build": fact.build,
        "build_number": fact.build_number,
        "timestamp": fact.timestamp,
        "subdir": fact.subdir,
        "sha256": fact.sha256,
        "requires_python": fact.requires_python,
    })
}

/// The facts of every environment and platform of `lock`; `manifest` and `lockfile` are shown as given.
pub fn document(
    lock: &LockFile,
    wheels: Option<&crate::wheel::Data>,
    manifest: &Path,
    lockfile_path: &Path,
    base: &Path,
) -> Result<Value, CheckError> {
    let path = |p: &Path| crate::report::relative(p, base).0;
    let mut environments = Vec::new();
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment)? {
            let facts = lockfile::read(lock, &environment, Some(&platform))?;
            environments.push(json!({
                "name": environment,
                "platform": platform,
                "packages": facts.packages.iter().map(|fact| package(fact, wheels)).collect::<Vec<_>>(),
            }));
        }
    }
    Ok(json!({
        "version": VERSION,
        "tool": { "name": "pixi-policy", "version": env!("CARGO_PKG_VERSION") },
        "workspace": { "manifest": path(manifest), "lockfile": path(lockfile_path) },
        "environments": environments,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_purl_names_its_distribution() {
        assert_eq!(pypi_name("pkg:pypi/msgpack?source=compressed-mapping"), Some("msgpack"));
        assert_eq!(pypi_name("pkg:pypi/jinja2@3.1.2"), Some("jinja2"));
        assert_eq!(pypi_name("pkg:conda/x"), None);
    }

    #[test]
    fn every_package_has_its_origin_and_license_status() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        let doc = document(
            &lock,
            None,
            Path::new("pixi.toml"),
            Path::new("pixi.lock"),
            Path::new("."),
        )
        .unwrap();
        let types: std::collections::BTreeSet<&str> = doc["environments"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|env| env["packages"].as_array().unwrap())
            .map(|package| package["origin"]["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types.into_iter().collect::<Vec<_>>(),
            ["channel", "git", "index", "path", "url"]
        );
    }
}
