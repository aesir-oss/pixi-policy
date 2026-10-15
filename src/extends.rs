//! `[policy] extends` (#1): a policy built on others. The bases apply in order, each on top of the ones before, and the
//! extending file last. How each key combines is in [`crate::keys::Merge`]: lists of what is denied add up, and a
//! value or an allow list may be tightened freely but loosened only when every file that set it lists the key in
//! `[policy] overridable` (decided on #1). A value counts as a file's when it wrote it, or wrote the table whose
//! default turns the value's rule on. Waivers stay with the file that holds them.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::fetch::{Remote, Settings, fetch, join, pinned};
use crate::keys::{KEYS, Key, Merge, TABLES};
use crate::policy::{Policy, PolicyError};
use crate::rules::licenses::expand;
use crate::rules::sources::{channel_covered, index_allowed};

/// Where a value came from: the file, and the files whose stricter value it loosened under their `overridable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub source: String,
    pub loosens: Vec<String>,
}

/// A policy with everything it extends merged in.
#[derive(Debug)]
pub struct Resolved {
    pub policy: Policy,
    /// The merged keys as TOML, without `[policy]` and `[[waivers]]`.
    pub table: toml::Table,
    /// Every file read, bases first and the policy itself last.
    pub files: Vec<String>,
    /// Where each key's value came from, by key ID; a list that adds up has one origin per entry.
    pub origins: BTreeMap<String, Vec<Origin>>,
    /// The policy's own `[[waivers]]`, as written.
    pub waivers: Vec<toml::Value>,
}

/// Read the policy at `path` and every policy it extends, with the cache and network the environment allows.
pub fn resolve(path: &Path) -> Result<Resolved, PolicyError> {
    resolve_with(path, &Settings::from_env())
}

/// [`resolve`], with the cache and network given.
pub fn resolve_with(path: &Path, settings: &Settings) -> Result<Resolved, PolicyError> {
    let mut chain = Chain {
        settings: settings.clone(),
        ..Chain::default()
    };
    let shown = path.display().to_string();
    let (policy, raw) = chain
        .visit(&Place::File(path.to_path_buf()), &shown, None)?
        .expect("the first file is never seen before");
    let waivers = raw
        .get("waivers")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let policy = if chain.files.len() == 1 {
        policy
    } else {
        let text = toml::to_string(&chain.table).expect("a merged policy is TOML");
        let mut merged = Policy::parse(&text, &shown)?;
        merged.waivers = policy.waivers;
        merged.policy = policy.policy;
        merged
    };
    Ok(Resolved {
        policy,
        table: chain.table,
        files: chain.files,
        origins: chain.origins,
        waivers,
    })
}

/// Where a policy is read from.
#[derive(Debug, Clone)]
enum Place {
    File(PathBuf),
    Url(Remote),
}

#[derive(Default)]
struct Chain {
    settings: Settings,
    table: toml::Table,
    /// Every value each key has had, with the file that set it, in order.
    history: BTreeMap<String, Vec<(String, toml::Value)>>,
    origins: BTreeMap<String, Vec<Origin>>,
    /// Each file's `[policy] overridable`.
    overridable: BTreeMap<String, Vec<String>>,
    /// The files being read, by canonical path or URL, to catch a cycle.
    stack: Vec<(String, String)>,
    /// The files already merged: one reached twice is merged once.
    done: HashSet<String>,
    files: Vec<String>,
}

fn extends_error(path: &str, message: String, help: &str) -> PolicyError {
    PolicyError::Extends {
        path: path.to_string(),
        message,
        help: help.to_string(),
    }
}

impl Chain {
    /// Read `place` (shown as `shown`), its bases first, and merge it in. `None` when it was merged already.
    fn visit(
        &mut self,
        place: &Place,
        shown: &str,
        from: Option<&str>,
    ) -> Result<Option<(Policy, toml::Table)>, PolicyError> {
        let canonical = match (place, from) {
            (Place::Url(remote), _) => remote.url.clone(),
            (Place::File(path), _) if path.is_file() => {
                format!("{}", path.canonicalize().unwrap_or_else(|_| path.clone()).display())
            }
            (Place::File(_), None) => return Err(PolicyError::Missing { path: shown.into() }),
            (Place::File(_), Some(from)) => {
                return Err(extends_error(
                    from,
                    format!("extends {shown}, which does not exist"),
                    "correct the path in [policy] extends; it is relative to the file that names it",
                ));
            }
        };
        if let Some(at) = self.stack.iter().position(|(seen, _)| *seen == canonical) {
            let mut cycle: Vec<&str> = self.stack[at..].iter().map(|(_, name)| name.as_str()).collect();
            cycle.push(shown);
            return Err(extends_error(
                from.unwrap_or(shown),
                format!("extends itself: {}", cycle.join(" -> ")),
                "remove one of the extends entries so the policies form a chain",
            ));
        }
        if self.done.contains(&canonical) {
            return Ok(None);
        }
        let (mut policy, text) = match place {
            Place::File(path) => Policy::load_file(path)?,
            Place::Url(remote) => {
                let text = fetch(remote, &self.settings).map_err(|err| {
                    extends_error(
                        from.unwrap_or(shown),
                        format!("extends {shown}, which cannot be read: {err}"),
                        "check the URL and the network; once read, a pinned policy is cached and needs no network",
                    )
                })?;
                (Policy::parse(&text, shown)?, text)
            }
        };
        let mut raw: toml::Table = toml::from_str(&text).expect("Policy::parse accepted it");
        if let Some(advisories) = policy.advisories.as_mut()
            && !advisories.vex.is_empty()
        {
            let located = advisories
                .vex
                .iter()
                .map(|entry| vex_location(place, shown, entry))
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(table) = raw.get_mut("advisories").and_then(toml::Value::as_table_mut) {
                table.insert(
                    "vex".into(),
                    toml::Value::Array(located.iter().cloned().map(toml::Value::String).collect()),
                );
            }
            advisories.vex = located;
        }
        self.stack.push((canonical.clone(), shown.to_string()));
        for entry in policy.extends() {
            let base = match (place, entry.is_url()) {
                (_, true) => Place::Url(Remote {
                    url: entry.location().to_string(),
                    sha256: entry.sha256().map(str::to_string),
                }),
                (Place::File(_), false) => {
                    let dir = Path::new(shown).parent().unwrap_or(Path::new(""));
                    Place::File(tidy(&dir.join(entry.location())))
                }
                (Place::Url(remote), false) => {
                    let url = join(&remote.url, entry.location());
                    if !pinned(&url) {
                        return Err(extends_error(
                            shown,
                            format!("extends {}, which is {url} and not pinned", entry.location()),
                            "a policy fetched by its sha256 alone can extend only URLs that pin a tag or commit, \
                             or carry their own sha256",
                        ));
                    }
                    Place::Url(Remote { url, sha256: None })
                }
            };
            let name = match &base {
                Place::File(path) => path.display().to_string(),
                Place::Url(remote) => remote.url.clone(),
            };
            self.visit(&base, &name, Some(shown))?;
        }
        self.stack.pop();
        self.done.insert(canonical);
        self.merge(shown, &raw)?;
        self.overridable
            .insert(shown.to_string(), policy.overridable().to_vec());
        self.files.push(shown.to_string());
        Ok(Some((policy, raw)))
    }

    /// Merge one file's keys into the chain.
    fn merge(&mut self, source: &str, raw: &toml::Table) -> Result<(), PolicyError> {
        for table in TABLES.iter().filter(|table| **table != "policy") {
            if raw.contains_key(*table) && !self.table.contains_key(*table) {
                self.table
                    .insert((*table).to_string(), toml::Value::Table(toml::Table::new()));
            }
        }
        for key in KEYS.iter().filter(|key| !key.is_container()) {
            let written_table = match key.table {
                "" => Some(raw),
                table => raw.get(table).and_then(toml::Value::as_table),
            };
            let written = written_table.and_then(|table| table.get(key.name));
            match key.merge {
                Merge::Grows => {
                    if let Some(items) = written.and_then(toml::Value::as_array) {
                        self.grow(source, key, items)?;
                    }
                }
                Merge::Narrows | Merge::Stricter => {
                    let implicit = (!key.table.is_empty() && written_table.is_some())
                        .then(|| implicit(&key.id()))
                        .flatten();
                    if let Some(value) = written.cloned().or(implicit) {
                        self.set(source, key, value, written.is_some())?;
                    }
                }
                Merge::Table | Merge::Entry | Merge::Local => {}
            }
        }
        Ok(())
    }

    /// Add a list's entries, each once, and check a review entry does not accept what an earlier allow list did not.
    fn grow(&mut self, source: &str, key: &Key, items: &[toml::Value]) -> Result<(), PolicyError> {
        let id = key.id();
        let target = home(&mut self.table, key)
            .entry(key.name)
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .expect("a list that adds up is an array");
        let mut added = Vec::new();
        for item in items {
            if !target.contains(item) {
                target.push(item.clone());
                added.push(item.clone());
            }
        }
        let mut origins = Vec::new();
        for item in &added {
            let mut loosens = Vec::new();
            if id == "licenses.review" {
                // With an allow list, a review entry is also acceptable: adding one can accept a license it does not.
                let entry = item.as_str().unwrap_or_default();
                for (setter, allow) in self.history.get("licenses.allow").into_iter().flatten() {
                    let allow = strings(allow);
                    if setter == source || allow.is_empty() || license_covered(entry, &allow) {
                        continue;
                    }
                    self.permit(
                        source,
                        "licenses.allow",
                        setter,
                        &format!(
                            "adds {entry:?} to [licenses] review, which accepts it although [licenses] allow does not"
                        ),
                    )?;
                    loosens.push(setter.clone());
                }
            }
            origins.push(Origin {
                source: source.to_string(),
                loosens,
            });
        }
        self.origins.entry(id).or_default().extend(origins);
        Ok(())
    }

    /// Set a value, after checking it against every value the key had before.
    fn set(&mut self, source: &str, key: &Key, value: toml::Value, written: bool) -> Result<(), PolicyError> {
        let id = key.id();
        let mut loosens = Vec::new();
        for (setter, old) in self.history.get(&id).cloned().unwrap_or_default() {
            if let Some(detail) = looser(&id, &value, &old) {
                self.permit(source, &id, &setter, &format!("sets {} {detail}", key.path()))?;
                if !loosens.contains(&setter) {
                    loosens.push(setter);
                }
            }
        }
        self.history
            .entry(id.clone())
            .or_default()
            .push((source.to_string(), value.clone()));
        if written {
            home(&mut self.table, key).insert(key.name.to_string(), value);
            self.origins.insert(
                id,
                vec![Origin {
                    source: source.to_string(),
                    loosens,
                }],
            );
        }
        Ok(())
    }

    /// Whether `source` may loosen `id` as `setter` set it: only when `setter` lists it in overridable.
    fn permit(&self, source: &str, id: &str, setter: &str, what: &str) -> Result<(), PolicyError> {
        let allowed = self
            .overridable
            .get(setter)
            .is_some_and(|ids| ids.iter().any(|allowed| allowed == id));
        if allowed {
            return Ok(());
        }
        Err(extends_error(
            source,
            format!("{what}: that loosens {setter}, which does not list {id:?} in [policy] overridable"),
            &format!(
                "keep it at least as strict as {setter}, ask for {id:?} in its [policy] overridable, or waive the \
                 packages that need it with [[waivers]]"
            ),
        ))
    }
}

/// Where a `[advisories] vex` entry of the policy at `place` (shown as `shown`) is: a URL as it is, a path relative to
/// the policy's file, or to its URL when it was extended by URL (decided on #10).
fn vex_location(place: &Place, shown: &str, entry: &str) -> Result<String, PolicyError> {
    if entry.contains("://") {
        return Ok(entry.to_string());
    }
    match place {
        Place::File(_) => {
            let dir = Path::new(shown).parent().unwrap_or(Path::new(""));
            Ok(tidy(&dir.join(entry)).display().to_string())
        }
        Place::Url(remote) => {
            let url = join(&remote.url, entry);
            if pinned(&url) {
                Ok(url)
            } else {
                Err(extends_error(
                    shown,
                    format!("names the VEX {entry}, which is {url} and not pinned"),
                    "a policy fetched by its sha256 alone can name only VEX URLs that pin a tag or commit",
                ))
            }
        }
    }
}

/// The merged table `key` is in.
fn home<'a>(table: &'a mut toml::Table, key: &Key) -> &'a mut toml::Table {
    match key.table {
        "" => table,
        name => table
            .entry(name)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("a family is a table"),
    }
}

/// The value a key has when its file writes the table but not the key, if that default turns its rule on.
fn implicit(id: &str) -> Option<toml::Value> {
    match id {
        "manifest.wildcard-spec"
        | "manifest.python-pinned"
        | "lock.present"
        | "lock.complete"
        | "lock.in-sync"
        | "freshness.archived"
        | "hygiene.conda-pypi-duplicate" => Some(toml::Value::Boolean(true)),
        "licenses.unknown" | "licenses.ambiguous" | "advisories.unknown" | "freshness.unknown" => {
            Some(toml::Value::String("warn".into()))
        }
        "advisories.fail-on" => Some(toml::Value::String("high".into())),
        "advisories.known-exploited" | "python.older" => Some(toml::Value::String("error".into())),
        "python.newer" => Some(toml::Value::String("warn".into())),
        "advisories.pypi-mapping" => Some(toml::Value::String("prefix".into())),
        _ => None,
    }
}

fn strings(value: &toml::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the licenses `entry` accepts are all in `allow`. An -or-later entry is covered only by itself.
fn license_covered(entry: &str, allow: &[String]) -> bool {
    let Ok(base) = expand(allow) else { return false };
    let Ok(lists) = crate::license_policy::Lists::new(&base, &[]) else {
        return false;
    };
    let Ok(wanted) = expand(&[entry.to_string()]) else {
        return false;
    };
    wanted.iter().all(|id| {
        let open_ended = id.ends_with("-or-later") || id.ends_with('+');
        if open_ended {
            base.iter().any(|b| b.eq_ignore_ascii_case(id))
        } else {
            lists.evaluate(id).is_none()
        }
    })
}

/// How `new` is looser than `old` for key `id`, if it is.
fn looser(id: &str, new: &toml::Value, old: &toml::Value) -> Option<String> {
    let extra = |covered: &dyn Fn(&str, &[String]) -> bool| {
        let old = strings(old);
        let extra: Vec<String> = strings(new)
            .into_iter()
            .filter(|entry| !covered(entry, &old))
            .map(|entry| format!("{entry:?}"))
            .collect();
        (!extra.is_empty()).then(|| format!("to allow {}", extra.join(", ")))
    };
    match id {
        "sources.allowed-channels" => extra(&channel_covered),
        "sources.allowed-indexes" => extra(&|entry, old| index_allowed(entry, old)),
        "licenses.allow" => {
            if strings(old).is_empty() {
                None
            } else if strings(new).is_empty() {
                Some("to [], which accepts every license".into())
            } else {
                extra(&license_covered)
            }
        }
        "advisories.fail-on" => {
            let rank = |value: &toml::Value| match value.as_str() {
                Some("low") => 1,
                Some("medium") => 2,
                Some("high") => 3,
                _ => 4,
            };
            (rank(new) > rank(old)).then(|| format!("to {new} (it was {old})"))
        }
        "advisories.epss" => {
            let score = |value: &toml::Value| value.as_float().unwrap_or(1.0);
            (score(new) > score(old)).then(|| format!("to {new} (it was {old})"))
        }
        "advisories.pypi-mapping" => {
            (new.as_str() == Some("lock") && old.as_str() == Some("prefix")).then(|| format!("to {new} (it was {old})"))
        }
        "freshness.max-build-age-days" | "freshness.max-majors-behind" => {
            let limit = |value: &toml::Value| value.as_integer().unwrap_or(i64::MAX);
            (limit(new) > limit(old)).then(|| format!("to {new} (it was {old})"))
        }
        "python.version" => (new != old).then(|| format!("to {new} (it was {old})")),
        "licenses.unknown"
        | "licenses.ambiguous"
        | "advisories.unknown"
        | "advisories.known-exploited"
        | "freshness.unknown"
        | "python.older"
        | "python.newer" => {
            let rank = |value: &toml::Value| match value.as_str() {
                Some("allow") => 0,
                Some("error") => 2,
                _ => 1,
            };
            (rank(new) < rank(old)).then(|| format!("to {new} (it was {old})"))
        }
        "max-waiver-days" => {
            let days = |value: &toml::Value| match value.as_integer() {
                Some(0) | None => i64::MAX,
                Some(days) => days,
            };
            (days(new) > days(old)).then(|| format!("to {new} (it was {old})"))
        }
        // allow-git, allow-url and allow-path: true allows more.
        _ if id.starts_with("sources.allow-") => {
            (new.as_bool() == Some(true) && old.as_bool() == Some(false)).then(|| "to true (it was false)".into())
        }
        // The manifest and lock switches: false turns a rule off.
        _ => (new.as_bool() == Some(false) && old.as_bool() == Some(true)).then(|| "to false (it was true)".into()),
    }
}

/// `path` without `.` and with each `dir/..` dropped, so `app/../base.toml` reads `base.toml`.
fn tidy(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if matches!(out.components().next_back(), Some(Component::Normal(_))) => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// `pixi policy show --resolved`: the merged policy as TOML, each value followed by the file it comes from.
pub fn render(resolved: &Resolved) -> String {
    let local = resolved.files.last().map_or("", String::as_str);
    let mut out = format!(
        "# {local}, resolved: every policy it extends merged in, each value followed by the file it comes from.\n\
         # Read in order: {}\n",
        resolved.files.join(", ")
    );
    let comment = |id: &str, index: usize| -> String {
        let Some(origin) = resolved.origins.get(id).and_then(|origins| origins.get(index)) else {
            return String::new();
        };
        match origin.loosens.as_slice() {
            [] => format!("  # {}", origin.source),
            setters => format!(
                "  # {}, loosens {} (overridable there)",
                origin.source,
                setters.join(", ")
            ),
        }
    };
    let section = |out: &mut String, table: &toml::Table, keys: Vec<&Key>| {
        for key in keys {
            let Some(value) = table.get(key.name) else { continue };
            let id = key.id();
            match (key.merge, value.as_array()) {
                (Merge::Grows, Some(items)) => {
                    out.push_str(&format!("{} = [\n", key.name));
                    for (index, item) in items.iter().enumerate() {
                        out.push_str(&format!("  {item},{}\n", comment(&id, index)));
                    }
                    out.push_str("]\n");
                }
                _ => out.push_str(&format!("{} = {value}{}\n", key.name, comment(&id, 0))),
            }
        }
    };
    let top: Vec<&Key> = KEYS
        .iter()
        .filter(|key| key.table.is_empty() && !key.is_container() && key.merge != Merge::Local)
        .collect();
    if top.iter().any(|key| resolved.table.contains_key(key.name)) {
        out.push('\n');
        section(&mut out, &resolved.table, top);
    }
    for name in TABLES.iter().filter(|name| **name != "policy") {
        let Some(table) = resolved.table.get(*name).and_then(toml::Value::as_table) else {
            continue;
        };
        out.push_str(&format!("\n[{name}]\n"));
        section(&mut out, table, KEYS.iter().filter(|key| key.table == *name).collect());
    }
    if !resolved.waivers.is_empty() {
        let mut waivers = toml::Table::new();
        waivers.insert("waivers".into(), toml::Value::Array(resolved.waivers.clone()));
        out.push_str(&format!(
            "\n# Waivers apply from {local} only.\n{}",
            toml::to_string(&waivers).expect("waivers are TOML")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(dir: &Path, entries: &[(&str, &str)]) {
        for (name, text) in entries {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
    }

    fn resolve_in(dir: &Path, path: &str) -> Result<Resolved, PolicyError> {
        resolve(&dir.join(path))
    }

    #[test]
    fn lists_of_denials_add_up_and_values_from_the_extending_file_win() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                (
                    "base.toml",
                    "max-waiver-days = 180\n[bans]\ndeny = [{ name = \"pycrypto\" }]\n[licenses]\ndeny = [\"AGPL-*\"]\n",
                ),
                (
                    "app/pixi-policy.toml",
                    "max-waiver-days = 90\n[policy]\nextends = [\"../base.toml\"]\n[bans]\ndeny = [{ name = \"pycrypto\" }, \
                     { name = \"requests\", version = \"<2.32\" }]\n",
                ),
            ],
        );
        let resolved = resolve_in(dir.path(), "app/pixi-policy.toml").unwrap();
        let names: Vec<&str> = resolved
            .policy
            .bans
            .as_ref()
            .unwrap()
            .deny
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        assert_eq!(names, ["pycrypto", "requests"]);
        assert_eq!(resolved.policy.licenses.unwrap().deny, ["AGPL-*"]);
        assert_eq!(resolved.policy.max_waiver_days, Some(90));
        assert_eq!(resolved.files.len(), 2);
        let bans = &resolved.origins["bans.deny"];
        assert!(bans[0].source.ends_with("base.toml") && bans[1].source.ends_with("pixi-policy.toml"));
    }

    #[test]
    fn a_policy_that_extends_nothing_reads_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let text = "[sources]\nallow-git = false\n[[waivers]]\nrule = \"bans.deny\"\npackage = \"x\"\nreason = \"r\"\nexpires = 2027-01-01\n";
        files(dir.path(), &[("p.toml", text)]);
        let resolved = resolve_in(dir.path(), "p.toml").unwrap();
        let shown = dir.path().join("p.toml").display().to_string();
        assert_eq!(resolved.policy, Policy::parse(text, &shown).unwrap());
        assert_eq!(resolved.waivers.len(), 1);
    }

    #[test]
    fn tightening_merges_in_and_loosening_needs_the_base_to_allow_it() {
        let dir = tempfile::tempdir().unwrap();
        let base = "[sources]\nallowed-channels = [\"conda-forge\", \"bioconda\"]\nallow-git = false\n\
                    [licenses]\nallow = [\"MIT\", \"Apache-2.0\"]\n";
        files(dir.path(), &[("base.toml", base)]);
        let child = |body: &str| {
            std::fs::write(
                dir.path().join("p.toml"),
                format!("[policy]\nextends = [\"base.toml\"]\n{body}"),
            )
            .unwrap();
            resolve_in(dir.path(), "p.toml")
        };
        // Narrower lists and a stricter value merge in; a URL for a named channel is the same channel.
        let tight = child(
            "[sources]\nallowed-channels = [\"https://conda.anaconda.org/conda-forge\"]\n[licenses]\nallow = [\"MIT\"]\n\
             unknown = \"error\"\n",
        )
        .unwrap();
        assert_eq!(tight.policy.licenses.as_ref().unwrap().allow, ["MIT"]);
        assert_eq!(tight.policy.sources.as_ref().unwrap().allow_git, Some(false));
        for (body, wanted) in [
            (
                "[sources]\nallowed-channels = [\"conda-forge\", \"pytorch\"]\n",
                "to allow \"pytorch\"",
            ),
            ("[sources]\nallow-git = true\n", "sets [sources] allow-git to true"),
            (
                "[licenses]\nallow = [\"MIT\", \"GPL-3.0-only\"]\n",
                "to allow \"GPL-3.0-only\"",
            ),
            ("[licenses]\nallow = []\n", "accepts every license"),
            ("[licenses]\nunknown = \"allow\"\n", "to \"allow\" (it was \"warn\")"),
            ("[licenses]\nambiguous = \"allow\"\n", "to \"allow\" (it was \"warn\")"),
            (
                "[licenses]\nreview = [\"LGPL-3.0-only\"]\n",
                "adds \"LGPL-3.0-only\" to [licenses] review",
            ),
        ] {
            let err = child(body).unwrap_err().to_string();
            assert!(err.contains(wanted), "{body}: {err}");
            assert!(err.contains("which does not list"), "{err}");
        }
        // Once the base lists a key in overridable, loosening it is allowed and recorded.
        std::fs::write(
            dir.path().join("base.toml"),
            format!("{base}[policy]\noverridable = [\"sources.allow-git\", \"licenses.allow\"]\n"),
        )
        .unwrap();
        let loose = child("[sources]\nallow-git = true\n[licenses]\nallow = [\"MIT\", \"BSD-3-Clause\"]\n").unwrap();
        assert_eq!(loose.policy.sources.as_ref().unwrap().allow_git, Some(true));
        let origin = &loose.origins["sources.allow-git"][0];
        assert_eq!(origin.loosens.len(), 1, "{origin:?}");
        // Still not the keys it did not list.
        assert!(child("[sources]\nallowed-channels = [\"pytorch\"]\n").is_err());
    }

    #[test]
    fn advisory_thresholds_may_only_tighten() {
        let dir = tempfile::tempdir().unwrap();
        files(dir.path(), &[("base.toml", "[advisories]\nepss = 0.2\n")]);
        let child = |body: &str| {
            std::fs::write(
                dir.path().join("p.toml"),
                format!("[policy]\nextends = [\"base.toml\"]\n{body}"),
            )
            .unwrap();
            resolve_in(dir.path(), "p.toml")
        };
        let tight =
            child("[advisories]\nfail-on = \"medium\"\nepss = 0.1\nknown-exploited = \"error\"\nunknown = \"error\"\n")
                .unwrap();
        let advisories = tight.policy.advisories.unwrap();
        assert_eq!(advisories.epss, Some(0.1));
        assert_eq!(advisories.fail_on, Some(crate::advisories::Level::Medium));
        // The base's table alone set the defaults: high, error, warn and prefix.
        for (body, wanted) in [
            (
                "[advisories]\nfail-on = \"critical\"\n",
                "to \"critical\" (it was \"high\")",
            ),
            ("[advisories]\nepss = 0.5\n", "to 0.5 (it was 0.2)"),
            (
                "[advisories]\nknown-exploited = \"warn\"\n",
                "to \"warn\" (it was \"error\")",
            ),
            ("[advisories]\nunknown = \"allow\"\n", "to \"allow\" (it was \"warn\")"),
            (
                "[advisories]\npypi-mapping = \"lock\"\n",
                "to \"lock\" (it was \"prefix\")",
            ),
        ] {
            let err = child(body).unwrap_err().to_string();
            assert!(err.contains(wanted), "{body}: {err}");
        }
    }

    #[test]
    fn freshness_limits_may_only_tighten() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[(
                "base.toml",
                "[freshness]\nmax-build-age-days = 730\nmax-majors-behind = 2\n",
            )],
        );
        let child = |body: &str| {
            std::fs::write(
                dir.path().join("p.toml"),
                format!("[policy]\nextends = [\"base.toml\"]\n{body}"),
            )
            .unwrap();
            resolve_in(dir.path(), "p.toml")
        };
        let tight = child("[freshness]\nmax-build-age-days = 365\nmax-majors-behind = 1\n").unwrap();
        assert_eq!(tight.policy.freshness.unwrap().max_build_age_days, Some(365));
        for (body, wanted) in [
            ("[freshness]\nmax-build-age-days = 1000\n", "to 1000 (it was 730)"),
            ("[freshness]\nmax-majors-behind = 3\n", "to 3 (it was 2)"),
            ("[freshness]\narchived = false\n", "to false (it was true)"),
            ("[freshness]\nunknown = \"allow\"\n", "to \"allow\" (it was \"warn\")"),
        ] {
            let err = child(body).unwrap_err().to_string();
            assert!(err.contains(wanted), "{body}: {err}");
        }
    }

    #[test]
    fn the_python_standard_is_fixed_and_its_severities_only_tighten() {
        let dir = tempfile::tempdir().unwrap();
        files(dir.path(), &[("base.toml", "[python]\nversion = \"3.14\"\n")]);
        let child = |body: &str| {
            std::fs::write(
                dir.path().join("p.toml"),
                format!("[policy]\nextends = [\"base.toml\"]\n{body}"),
            )
            .unwrap();
            resolve_in(dir.path(), "p.toml")
        };
        let inherited = child("").unwrap().policy.python.unwrap();
        assert_eq!(
            (inherited.version.as_str(), inherited.older()),
            ("3.14", crate::policy::Action::Error)
        );
        let tight = child("[python]\nversion = \"3.14\"\nnewer = \"error\"\n").unwrap();
        assert_eq!(tight.policy.python.unwrap().newer(), crate::policy::Action::Error);
        for (body, wanted) in [
            ("[python]\nversion = \"3.13\"\n", "to \"3.13\" (it was \"3.14\")"),
            (
                "[python]\nversion = \"3.14\"\nolder = \"warn\"\n",
                "to \"warn\" (it was \"error\")",
            ),
            (
                "[python]\nversion = \"3.14\"\nnewer = \"allow\"\n",
                "to \"allow\" (it was \"warn\")",
            ),
        ] {
            let err = child(body).unwrap_err().to_string();
            assert!(err.contains(wanted), "{body}: {err}");
        }
    }

    #[test]
    fn a_table_turns_its_rules_on_for_every_file_after_it() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                ("base.toml", "[lock]\n[manifest]\nwildcard-spec = false\n"),
                (
                    "p.toml",
                    "[policy]\nextends = [\"base.toml\"]\n[lock]\nin-sync = false\n",
                ),
                (
                    "q.toml",
                    "[policy]\nextends = [\"base.toml\"]\n[manifest]\nwildcard-spec = true\npython-pinned = false\n",
                ),
            ],
        );
        let err = resolve_in(dir.path(), "p.toml").unwrap_err().to_string();
        assert!(err.contains("sets [lock] in-sync to false (it was true)"), "{err}");
        let err = resolve_in(dir.path(), "q.toml").unwrap_err().to_string();
        assert!(err.contains("[manifest] python-pinned"), "{err}");
        // Turning on what the base left off is tightening.
        std::fs::write(
            dir.path().join("q.toml"),
            "[policy]\nextends = [\"base.toml\"]\n[manifest]\nwildcard-spec = true\n",
        )
        .unwrap();
        let manifest = resolve_in(dir.path(), "q.toml").unwrap().policy.manifest.unwrap();
        assert_eq!(manifest.wildcard_spec, Some(true));
    }

    #[test]
    fn a_chain_is_checked_against_every_file_that_set_a_value() {
        // team.toml may loosen what it set itself, but not past what base.toml set and does not let go of.
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                ("base.toml", "max-waiver-days = 180\n"),
                (
                    "team.toml",
                    "max-waiver-days = 90\n[policy]\nextends = [\"base.toml\"]\noverridable = [\"max-waiver-days\"]\n",
                ),
                (
                    "ok.toml",
                    "max-waiver-days = 120\n[policy]\nextends = [\"team.toml\"]\n",
                ),
                ("bad.toml", "max-waiver-days = 0\n[policy]\nextends = [\"team.toml\"]\n"),
            ],
        );
        let ok = resolve_in(dir.path(), "ok.toml").unwrap();
        assert_eq!(ok.policy.max_waiver_days, Some(120));
        assert_eq!(ok.files.len(), 3);
        let err = resolve_in(dir.path(), "bad.toml").unwrap_err().to_string();
        assert!(err.contains("loosens") && err.contains("base.toml"), "{err}");
    }

    #[test]
    fn a_cycle_and_a_missing_base_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                ("a.toml", "[policy]\nextends = [\"b.toml\"]\n"),
                ("b.toml", "[policy]\nextends = [\"a.toml\"]\n"),
                ("gone.toml", "[policy]\nextends = [\"nope.toml\"]\n"),
            ],
        );
        let err = resolve_in(dir.path(), "a.toml").unwrap_err().to_string();
        assert!(
            err.contains("extends itself") && err.contains("a.toml -> ") && err.contains("b.toml"),
            "{err}"
        );
        let err = resolve_in(dir.path(), "gone.toml").unwrap_err().to_string();
        assert!(err.contains("nope.toml, which does not exist"), "{err}");
        assert!(matches!(
            resolve_in(dir.path(), "none.toml"),
            Err(PolicyError::Missing { .. })
        ));
    }

    #[test]
    fn a_base_reached_twice_is_merged_once() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                ("root.toml", "[licenses]\ndeny = [\"AGPL-*\"]\n"),
                ("a.toml", "[policy]\nextends = [\"root.toml\"]\n"),
                ("b.toml", "[policy]\nextends = [\"./root.toml\"]\n"),
                ("p.toml", "[policy]\nextends = [\"a.toml\", \"b.toml\"]\n"),
            ],
        );
        let resolved = resolve_in(dir.path(), "p.toml").unwrap();
        assert_eq!(resolved.policy.licenses.unwrap().deny, ["AGPL-*"]);
        assert_eq!(resolved.files.len(), 4);
    }

    #[test]
    fn show_resolved_names_where_each_value_comes_from() {
        let dir = tempfile::tempdir().unwrap();
        files(
            dir.path(),
            &[
                (
                    "base.toml",
                    "[freshness]\nmax-build-age-days = 730\n[sources]\nallow-git = false\n[bans]\ndeny = [{ name = \"pycrypto\" }]\n[policy]\noverridable = [\"sources.allow-git\"]\n",
                ),
                (
                    "p.toml",
                    "max-waiver-days = 90\n[policy]\nextends = [\"base.toml\"]\n[sources]\nallow-git = true\n[bans]\n\
                     deny = [{ name = \"requests\" }]\n[[waivers]]\nrule = \"bans.deny\"\npackage = \"requests\"\n\
                     reason = \"r\"\nexpires = 2027-01-01\n",
                ),
            ],
        );
        let text = render(&resolve_in(dir.path(), "p.toml").unwrap());
        let base = dir.path().join("base.toml").display().to_string();
        let local = dir.path().join("p.toml").display().to_string();
        assert!(text.contains(&format!("# Read in order: {base}, {local}\n")), "{text}");
        assert!(text.contains(&format!("max-waiver-days = 90  # {local}\n")), "{text}");
        assert!(
            text.contains(&format!("[freshness]\nmax-build-age-days = 730  # {base}\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "allow-git = true  # {local}, loosens {base} (overridable there)\n"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("deny = [\n  {{ name = \"pycrypto\" }},  # {base}\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("# Waivers apply from {local} only.\n[[waivers]]\n")),
            "{text}"
        );
        // What it prints is a policy that reads back to the same keys.
        let merged = Policy::parse(&text, "shown.toml").unwrap();
        assert_eq!(merged.bans.unwrap().deny.len(), 2);
    }

    #[test]
    fn a_url_base_is_fetched_once_and_read_from_the_cache_after() {
        const BASE: &str = "[bans]\ndeny = [{ name = \"pycrypto\" }]\n";
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = crate::fetch::tests::serve(BASE, 1);
        let sha = crate::fetch::sha256(BASE.as_bytes());
        files(
            dir.path(),
            &[(
                "p.toml",
                &format!(
                    "[policy]\nextends = [{{ url = \"{url}\", sha256 = \"{sha}\" }}]\n[bans]\ndeny = [{{ name = \"x\" }}]\n"
                ),
            )],
        );
        let online = Settings {
            cache: Some(dir.path().join("cache")),
            offline: false,
        };
        let resolved = resolve_with(&dir.path().join("p.toml"), &online).unwrap();
        assert_eq!(resolved.files[0], url);
        assert_eq!(resolved.policy.bans.unwrap().deny.len(), 2);
        server.join().unwrap();
        let offline = Settings {
            offline: true,
            ..online.clone()
        };
        let again = resolve_with(&dir.path().join("p.toml"), &offline).unwrap();
        assert_eq!(again.origins["bans.deny"][0].source, url);
        // Nothing cached and no network: an error that names the URL.
        let empty = Settings {
            cache: Some(dir.path().join("empty")),
            offline: true,
        };
        let err = resolve_with(&dir.path().join("p.toml"), &empty)
            .unwrap_err()
            .to_string();
        assert!(err.contains(&format!("extends {url}, which cannot be read")), "{err}");
    }

    #[test]
    fn a_vex_entry_is_found_beside_the_policy_that_names_it() {
        let file = Place::File(PathBuf::from("shared/base.toml"));
        assert_eq!(
            vex_location(&file, "shared/base.toml", "../vex/a.json").unwrap(),
            Path::new("vex").join("a.json").display().to_string()
        );
        let pinned = Place::Url(crate::fetch::Remote {
            url: "https://example.com/acme/v3/base.toml".into(),
            sha256: None,
        });
        assert_eq!(
            vex_location(&pinned, "x", "vex.json").unwrap(),
            "https://example.com/acme/v3/vex.json"
        );
        assert_eq!(
            vex_location(&pinned, "x", "https://example.com/v1/other.json").unwrap(),
            "https://example.com/v1/other.json"
        );
        let by_sha = Place::Url(crate::fetch::Remote {
            url: "http://intranet/base.toml".into(),
            sha256: Some("0".repeat(64)),
        });
        let err = vex_location(&by_sha, "http://intranet/base.toml", "vex.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not pinned"), "{err}");
    }

    #[test]
    fn a_relative_entry_in_a_url_base_must_be_pinned_too() {
        const BASE: &str = "[policy]\nextends = [\"team.toml\"]\n";
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = crate::fetch::tests::serve(BASE, 1);
        let sha = crate::fetch::sha256(BASE.as_bytes());
        files(
            dir.path(),
            &[(
                "p.toml",
                &format!("[policy]\nextends = [{{ url = \"{url}\", sha256 = \"{sha}\" }}]\n"),
            )],
        );
        let settings = Settings {
            cache: Some(dir.path().join("cache")),
            offline: false,
        };
        let err = resolve_with(&dir.path().join("p.toml"), &settings)
            .unwrap_err()
            .to_string();
        assert!(err.contains("/team.toml and not pinned"), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn tidy_drops_dots() {
        assert_eq!(tidy(Path::new("app/../base.toml")), PathBuf::from("base.toml"));
        assert_eq!(tidy(Path::new("./a/./b.toml")), PathBuf::from("a/b.toml"));
        assert_eq!(tidy(Path::new("../x.toml")), PathBuf::from("../x.toml"));
    }
}
