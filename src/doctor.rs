//! `pixi policy doctor` (#76): whether each upstream a run needs answers, what the caches hold, and whether the
//! workspace is in a state `check` can judge. With a policy, only the upstreams it turns on are asked; without one, or
//! with `--all`, every one is (decided on #76).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use rattler_lock::LockFile;

use crate::check::Severity;
use crate::fetch::Unanswered;
use crate::lockfile::{self, Kind};
use crate::policy::{Action, Policy, PypiMapping};
use crate::workspace::Workspace;

/// One service a run may ask, and where its address came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub service: String,
    pub url: String,
    /// `default`, the variable that set it, or the file that names it.
    pub source: String,
    /// A file rather than a service's address: a status of 400 or more means it is not there.
    pub document: bool,
}

/// What the doctor is asked about.
pub struct Input<'a> {
    pub cwd: &'a Path,
    pub manifest_path: Option<&'a Path>,
    pub policy_path: Option<&'a Path>,
    pub all: bool,
}

/// How the doctor reaches the world, so the tests need neither a network nor pixi.
pub struct World<'a> {
    pub var: &'a dyn Fn(&str) -> Option<OsString>,
    pub probe: &'a (dyn Fn(&str) -> Result<u16, Unanswered> + Sync),
    pub pixi: crate::rules::lock::Pixi<'a>,
    pub now: SystemTime,
}

/// The report, and whether it found a problem (exit 1).
pub fn run(input: &Input<'_>, world: &World<'_>) -> (String, bool) {
    let mut out = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    let settings = crate::fetch::Settings {
        cache: crate::fetch::cache_dir(world.var).map(|(dir, _)| dir),
        offline: crate::fetch::offline(world.var),
    };

    let workspace = Workspace::find(input.manifest_path, input.cwd);
    let mut policy = None;
    let mut lock = None;
    let mut remote_policies = Vec::new();
    let mut workspace_lines = Vec::new();
    match &workspace {
        Err(err) => workspace_lines.push(format!("  none: {err}")),
        Ok(ws) => {
            let shown = |path: &Path| crate::report::relative(path, input.cwd).0;
            workspace_lines.push(format!("  manifest  {}", shown(&ws.manifest)));
            match ws.has_lockfile() {
                false => {
                    workspace_lines.push(format!("  lockfile  {}: missing", shown(&ws.lockfile)));
                    problems.push("the workspace has no pixi.lock".into());
                }
                true => match crate::check::load_lockfile(&ws.lockfile) {
                    Ok(read) => {
                        let version = format_version(&ws.lockfile).map_or(String::new(), |v| format!(", format {v}"));
                        workspace_lines.push(format!("  lockfile  {}{version}", shown(&ws.lockfile)));
                        lock = Some(read);
                    }
                    Err(err) => {
                        workspace_lines.push(format!("  lockfile  {}: unreadable: {err}", shown(&ws.lockfile)));
                        problems.push("pixi.lock cannot be read".into());
                    }
                },
            }
            let path = ws.policy_path(input.policy_path);
            match path.is_file() {
                false => workspace_lines.push(format!(
                    "  policy    {}: none, so every upstream is asked",
                    shown(&path)
                )),
                true => match crate::extends::resolve_with(&path, &settings) {
                    Ok(resolved) => {
                        workspace_lines.push(format!("  policy    {}", shown(&path)));
                        let bases = &resolved.files[..resolved.files.len().saturating_sub(1)];
                        for file in bases {
                            workspace_lines.push(format!("  extends   {}", link(file, settings.cache.as_deref())));
                            if file.contains("://") {
                                remote_policies.push(file.clone());
                            }
                        }
                        policy = Some(resolved.policy);
                    }
                    Err(err) => {
                        workspace_lines.push(format!("  policy    {}: cannot be read: {err}", shown(&path)));
                        problems.push("the policy cannot be read".into());
                    }
                },
            }
            if let Some((line, problem)) = lock_state(ws, lock.as_ref(), world.pixi) {
                workspace_lines.push(line);
                problems.extend(problem);
            }
        }
    }

    let all = input.all || policy.is_none();
    let wanted = upstreams(policy.as_ref(), lock.as_ref(), all, &remote_policies, world.var);
    out.push(match all {
        true => "Upstreams (every one):".to_string(),
        false => "Upstreams (those the policy uses; --all for every one):".to_string(),
    });
    if wanted.is_empty() {
        out.push("  none: the policy needs no network".into());
    }
    let answers = probe_all(&wanted, settings.offline, world.probe);
    let width = wanted.iter().map(|u| u.service.len()).max().unwrap_or(0);
    for (upstream, answer) in wanted.iter().zip(&answers) {
        let (state, detail) = match answer {
            None => ("skipped", "offline".to_string()),
            Some((Ok(status), took)) if *status < 400 => ("ok", format!("HTTP {status}, {} ms", took.as_millis())),
            Some((Ok(status), _)) if upstream.document => {
                problems.push(format!("{} is not served (HTTP {status})", upstream.service));
                ("failed", format!("HTTP {status}: the file is not there"))
            }
            // A service's base address is often not a document: any answer means it is reachable.
            Some((Ok(status), took)) => ("reachable", format!("HTTP {status}, {} ms", took.as_millis())),
            Some((Err(why), _)) => {
                problems.push(format!("{} is unreachable ({})", upstream.service, why.layer));
                ("failed", format!("{}: {}", why.layer, why.error))
            }
        };
        let source = match upstream.source.as_str() {
            "default" => String::new(),
            source => format!(" ({source})"),
        };
        out.push(format!(
            "  {state:<9} {:<width$}  {}{source}: {detail}",
            upstream.service, upstream.url
        ));
    }

    out.push(String::new());
    match &settings.cache {
        None => out.push("Caches: none, no cache directory could be found".into()),
        Some(dir) => {
            out.push(format!("Caches in {}:", dir.display()));
            let caches = caches(dir, world.now);
            if caches.is_empty() {
                out.push("  empty: every run fetches what it needs".into());
            }
            for (name, entries, newest) in caches {
                let newest = newest.map_or(String::new(), |age| format!(", newest {} ago", ago(age)));
                out.push(format!("  {name:<12} {entries} files{newest}"));
            }
        }
    }

    out.push(String::new());
    out.push(match &workspace {
        Ok(ws) => format!("Workspace {}:", ws.root.display()),
        Err(_) => "Workspace:".to_string(),
    });
    out.extend(workspace_lines);
    out.push(String::new());
    out.push(match problems.len() {
        0 => "No problems found.".to_string(),
        1 => format!("1 problem: {}.", problems[0]),
        n => format!("{n} problems: {}.", problems.join("; ")),
    });
    out.push(String::new());
    (out.join("\n"), !problems.is_empty())
}

/// The services `policy` turns on, or every one when `all`; channels come from `lock`, policies and VEX documents
/// from the policy.
pub fn upstreams(
    policy: Option<&Policy>,
    lock: Option<&LockFile>,
    all: bool,
    remote_policies: &[String],
    var: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<Upstream> {
    let endpoint = |service: &str, name: &str, default: &str, document: bool| {
        let set = var(name)
            .map(|value| value.to_string_lossy().trim().to_string())
            .filter(|value| !value.is_empty());
        Upstream {
            service: service.into(),
            url: set.clone().unwrap_or_else(|| default.into()),
            source: set.map_or("default".to_string(), |_| name.to_string()),
            document,
        }
    };
    let advisories = policy.and_then(|p| p.advisories.as_ref());
    let freshness = policy.and_then(|p| p.freshness.as_ref());
    let on = |used: bool| all || used;
    let mut out = Vec::new();
    if on(advisories.is_some()) {
        out.push(endpoint(
            "OSV",
            "PIXI_POLICY_OSV_URL",
            crate::advisories::OSV_URL,
            false,
        ));
    }
    if on(advisories.is_some_and(|a| a.known_exploited() != Action::Allow)) {
        out.push(endpoint(
            "CISA KEV",
            "PIXI_POLICY_KEV_URL",
            crate::advisories::KEV_URL,
            true,
        ));
    }
    if on(advisories.is_some_and(|a| a.epss.is_some())) {
        out.push(endpoint(
            "EPSS",
            "PIXI_POLICY_EPSS_URL",
            crate::advisories::EPSS_URL,
            true,
        ));
    }
    let mapping_for_advisories = advisories.is_some_and(|a| a.pypi_mapping() == PypiMapping::Prefix);
    let mapping_for_hygiene = policy
        .and_then(|p| p.hygiene.as_ref())
        .is_some_and(|h| h.conda_pypi_duplicate());
    if on(mapping_for_advisories || mapping_for_hygiene) {
        out.push(endpoint(
            "conda-PyPI mapping",
            "PIXI_POLICY_MAPPING_URL",
            crate::advisories::MAPPING_URL,
            true,
        ));
    }
    let limits = freshness.is_some_and(|f| f.max_build_age_days.is_some() || f.max_majors_behind.is_some());
    if on(limits && freshness.is_some_and(|f| f.pypi())) {
        out.push(endpoint(
            "PyPI",
            "PIXI_POLICY_PYPI_URL",
            crate::freshness::PYPI_URL,
            false,
        ));
    }
    if on(policy.is_some_and(|p| p.licenses.is_some())) {
        out.push(endpoint(
            "PyPI wheels",
            "PIXI_POLICY_WHEEL_URL",
            crate::wheel::FILES_HOST,
            false,
        ));
    }
    if on(freshness.is_some_and(|f| f.archived())) {
        out.push(endpoint(
            "feedstock list",
            "PIXI_POLICY_FEEDSTOCKS_URL",
            crate::freshness::FEEDSTOCKS_URL,
            true,
        ));
        out.push(endpoint(
            "feedstock outputs",
            "PIXI_POLICY_FEEDSTOCK_OUTPUTS_URL",
            crate::freshness::OUTPUTS_URL,
            true,
        ));
    }
    if on(freshness.is_some_and(|f| f.max_majors_behind.is_some())) {
        for channel in lock.map(channels).unwrap_or_default() {
            out.push(Upstream {
                service: "channel".into(),
                url: channel,
                source: "pixi.lock".into(),
                document: false,
            });
        }
    }
    for url in remote_policies {
        out.push(Upstream {
            service: "extended policy".into(),
            url: url.clone(),
            source: "extends".into(),
            document: true,
        });
    }
    for url in advisories.iter().flat_map(|a| &a.vex).filter(|l| l.contains("://")) {
        out.push(Upstream {
            service: "VEX document".into(),
            url: url.clone(),
            source: "[advisories] vex".into(),
            document: true,
        });
    }
    out
}

/// Every conda channel a package in `lock` comes from.
fn channels(lock: &LockFile) -> Vec<String> {
    let mut out = BTreeSet::new();
    for environment in lockfile::environment_names(lock) {
        for platform in lockfile::platform_names(lock, &environment).unwrap_or_default() {
            let Ok(facts) = lockfile::read(lock, &environment, Some(&platform)) else {
                continue;
            };
            out.extend(
                facts
                    .packages
                    .into_iter()
                    .filter(|fact| fact.kind == Kind::CondaBinary)
                    .filter_map(|fact| fact.channel_url),
            );
        }
    }
    out.into_iter().collect()
}

type Answer = Option<(Result<u16, Unanswered>, Duration)>;

/// Ask every upstream at once; offline, none is asked.
fn probe_all(
    upstreams: &[Upstream],
    offline: bool,
    probe: &(dyn Fn(&str) -> Result<u16, Unanswered> + Sync),
) -> Vec<Answer> {
    if offline {
        return vec![None; upstreams.len()];
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = upstreams
            .iter()
            .map(|upstream| {
                scope.spawn(move || {
                    let started = Instant::now();
                    let answer = probe(&upstream.url);
                    Some((answer, started.elapsed()))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or(None)).collect()
    })
}

/// A policy the chain extends, with whether it is pinned and cached.
fn link(file: &str, cache: Option<&Path>) -> String {
    if !file.contains("://") {
        return format!("{file} (a local file)");
    }
    let pinned = match crate::fetch::pinned(file) {
        true => "pinned",
        false => "not pinned: a tag, a commit or a sha256 makes it so",
    };
    let cached = cache
        .map(|dir| dir.join("extends").join(crate::fetch::sha256(file.as_bytes())))
        .is_some_and(|path| path.is_file());
    let cached = if cached { "cached" } else { "not cached" };
    format!("{file} ({pinned}; {cached})")
}

/// pixi.lock's format version, from its `version:` line.
fn format_version(lockfile: &Path) -> Option<String> {
    let text = std::fs::read_to_string(lockfile).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("version:"))
        .map(|v| v.trim().to_string())
}

/// Whether pixi.lock still satisfies the manifest and covers it, as the `lock.*` rules judge it, with the problem
/// when it does not.
fn lock_state(
    ws: &Workspace,
    lock: Option<&LockFile>,
    pixi: crate::rules::lock::Pixi<'_>,
) -> Option<(String, Option<String>)> {
    let lock = lock?;
    let manifest = match crate::manifest::Manifest::load(&ws.manifest) {
        Ok(manifest) => manifest,
        Err(err) => {
            return Some((
                format!("  in sync   unknown: pixi.toml cannot be read: {err}"),
                Some("pixi.toml cannot be read".into()),
            ));
        }
    };
    let every = Policy::parse("[lock]\n", "pixi policy doctor").ok()?;
    let findings = crate::rules::lock::check(&every, ws, &manifest, Some(lock), pixi);
    let errors: Vec<&str> = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| f.message.as_str())
        .collect();
    if let Some(first) = errors.first() {
        let more = match errors.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        return Some((
            format!("  in sync   no: {first}{more}"),
            Some("pixi.lock is not current with the manifest: run `pixi lock`".into()),
        ));
    }
    Some(match findings.first() {
        Some(warning) => (format!("  in sync   unknown: {}", warning.message), None),
        None => ("  in sync   yes".into(), None),
    })
}

/// Each directory in the cache: its name, how many files it holds, and how old the newest is.
pub fn caches(dir: &Path, now: SystemTime) -> Vec<(String, usize, Option<Duration>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.into_iter()
        .map(|dir| {
            let (mut count, mut newest) = (0, None);
            walk(&dir, now, &mut count, &mut newest);
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, count, newest)
        })
        .collect()
}

fn walk(dir: &Path, now: SystemTime, count: &mut usize, newest: &mut Option<Duration>) {
    for path in std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()) {
        if path.is_dir() {
            walk(&path, now, count, newest);
            continue;
        }
        *count += 1;
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .map(|modified| now.duration_since(modified).unwrap_or_default());
        if let Some(age) = age {
            *newest = Some(newest.map_or(age, |current: Duration| current.min(age)));
        }
    }
}

/// How long ago, in the unit a person reads.
pub fn ago(age: Duration) -> String {
    match age.as_secs() {
        s @ 0..=90 => format!("{s}s"),
        s @ 91..=5400 => format!("{}m", s / 60),
        s @ 5401..=172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Output;

    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lock")
            .join(name)
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name| {
            vars.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    fn pixi_says(code: i32, stderr: &'static str) -> impl Fn(&Path, &str) -> std::io::Result<Output> {
        move |_, _| {
            Ok(Output {
                status: crate::rules::lock::exit_status(code),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            })
        }
    }

    /// The doctor's report on lock fixture `name` with `policy` (none when empty) and the probe given.
    fn doctor(
        name: &str,
        policy: &str,
        vars: &[(&str, &str)],
        probe: &(dyn Fn(&str) -> Result<u16, Unanswered> + Sync),
        pixi: crate::rules::lock::Pixi<'_>,
    ) -> (String, bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi-policy.toml");
        if !policy.is_empty() {
            std::fs::write(&path, policy).unwrap();
        }
        let cache = dir.path().join("cache");
        let mut vars: Vec<(&str, &str)> = vars.to_vec();
        let cache_text = cache.to_string_lossy().into_owned();
        vars.push(("PIXI_POLICY_CACHE_DIR", &cache_text));
        let var = env(&vars);
        let cwd = fixture(name);
        let input = Input {
            cwd: &cwd,
            manifest_path: None,
            policy_path: Some(&path),
            all: false,
        };
        let world = World {
            var: &var,
            probe,
            pixi,
            now: SystemTime::now(),
        };
        run(&input, &world)
    }

    const ONLY_OSV: &str = "[advisories]\nknown-exploited = \"allow\"\npypi-mapping = \"lock\"\n";

    #[test]
    fn a_healthy_workspace_asks_only_what_its_policy_uses() {
        let asked = std::sync::Mutex::new(Vec::new());
        let probe = |url: &str| {
            asked.lock().unwrap().push(url.to_string());
            Ok(404)
        };
        let (text, failed) = doctor("in-sync", ONLY_OSV, &[], &probe, &pixi_says(0, ""));
        assert!(!failed, "{text}");
        assert_eq!(*asked.lock().unwrap(), [crate::advisories::OSV_URL]);
        assert!(
            text.contains("Upstreams (those the policy uses; --all for every one):"),
            "{text}"
        );
        assert!(
            text.contains("  reachable OSV  https://api.osv.dev: HTTP 404, "),
            "{text}"
        );
        assert!(text.contains("  in sync   yes\n"), "{text}");
        assert!(text.contains("  lockfile  pixi.lock, format 7"), "{text}");
        assert!(text.contains("  empty: every run fetches what it needs"), "{text}");
        assert!(text.ends_with("No problems found.\n"), "{text}");
    }

    #[test]
    fn an_unreachable_upstream_or_a_missing_file_is_a_problem() {
        let probe = |_: &str| {
            Err(Unanswered {
                layer: "TLS",
                error: "invalid peer certificate: UnknownIssuer".into(),
            })
        };
        let vars = [("PIXI_POLICY_OSV_URL", "https://osv.mirror.example")];
        let (text, failed) = doctor("in-sync", ONLY_OSV, &vars, &probe, &pixi_says(0, ""));
        assert!(failed);
        assert!(
            text.contains(
                "  failed    OSV  https://osv.mirror.example (PIXI_POLICY_OSV_URL): TLS: invalid peer certificate: \
                 UnknownIssuer"
            ),
            "{text}"
        );
        assert!(text.ends_with("1 problem: OSV is unreachable (TLS).\n"), "{text}");

        let policy = "[advisories]\npypi-mapping = \"lock\"\n";
        let probe = |url: &str| Ok(if url == crate::advisories::KEV_URL { 404 } else { 200 });
        let (text, failed) = doctor("in-sync", policy, &[], &probe, &pixi_says(0, ""));
        assert!(failed);
        assert!(text.contains("  failed    CISA KEV  "), "{text}");
        assert!(text.contains(": HTTP 404: the file is not there"), "{text}");
        assert!(
            text.ends_with("1 problem: CISA KEV is not served (HTTP 404).\n"),
            "{text}"
        );
    }

    #[test]
    fn a_stale_lock_is_a_problem_and_pixi_missing_is_not() {
        let probe = |_: &str| Ok(200);
        let stale = pixi_says(1, "Error: the lock-file is not up-to-date with the workspace");
        let (text, failed) = doctor("stale", ONLY_OSV, &[], &probe, &stale);
        assert!(failed);
        assert!(text.contains("  in sync   no: "), "{text}");
        assert!(
            text.contains("pixi.lock is not current with the manifest: run `pixi lock`"),
            "{text}"
        );

        let missing = |_: &Path, _: &str| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
        let (text, failed) = doctor("in-sync", ONLY_OSV, &[], &probe, &missing);
        assert!(!failed, "{text}");
        assert!(text.contains("  in sync   unknown: "), "{text}");

        let (text, failed) = doctor("missing-lockfile", ONLY_OSV, &[], &probe, &missing);
        assert!(failed);
        assert!(text.contains("  lockfile  pixi.lock: missing"), "{text}");
    }

    #[test]
    fn offline_nothing_is_asked() {
        let probe = |url: &str| -> Result<u16, Unanswered> { panic!("asked {url} offline") };
        let (text, failed) = doctor(
            "in-sync",
            "",
            &[("PIXI_POLICY_OFFLINE", "1")],
            &probe,
            &pixi_says(0, ""),
        );
        assert!(!failed, "{text}");
        assert!(text.contains("Upstreams (every one):"), "{text}");
        assert!(
            text.contains("pixi-policy.toml: none, so every upstream is asked"),
            "{text}"
        );
        assert!(text.contains("  skipped   OSV "), "{text}");
        assert!(text.contains("  skipped   channel             https://conda.anaconda.org/conda-forge/ (pixi.lock)"));
    }

    #[test]
    fn a_policy_that_needs_no_network_says_so_and_an_unreadable_one_is_a_problem() {
        let probe = |url: &str| -> Result<u16, Unanswered> { panic!("asked {url}") };
        let (text, failed) = doctor("in-sync", "[bans]\n", &[], &probe, &pixi_says(0, ""));
        assert!(!failed, "{text}");
        assert!(text.contains("  none: the policy needs no network"), "{text}");

        let probe = |_: &str| Ok(200);
        let (text, failed) = doctor("in-sync", "[bans\n", &[], &probe, &pixi_says(0, ""));
        assert!(failed);
        assert!(text.contains(": cannot be read: "), "{text}");
    }

    #[test]
    fn without_a_workspace_every_upstream_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let var = env(&[]);
        let probe = |_: &str| Ok(200);
        let input = Input {
            cwd: dir.path(),
            manifest_path: None,
            policy_path: None,
            all: false,
        };
        let world = World {
            var: &var,
            probe: &probe,
            pixi: &pixi_says(0, ""),
            now: SystemTime::now(),
        };
        let (text, failed) = run(&input, &world);
        assert!(!failed, "{text}");
        assert!(text.contains("Workspace:\n  none: "), "{text}");
        assert!(
            text.contains("Caches: none, no cache directory could be found"),
            "{text}"
        );
        for service in [
            "OSV",
            "CISA KEV",
            "EPSS",
            "conda-PyPI mapping",
            "PyPI",
            "PyPI wheels",
            "feedstock list",
        ] {
            assert!(text.contains(&format!("  ok        {service} ")), "{service} in {text}");
        }
    }

    #[test]
    fn upstreams_follow_the_policy_switches() {
        let names = |policy: &str| {
            let policy = Policy::parse(policy, "p.toml").unwrap();
            let remote = ["https://example.com/v1/base.toml".to_string()];
            upstreams(Some(&policy), None, false, &remote, &env(&[]))
                .into_iter()
                .map(|u| u.service)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names("[advisories]\nepss = 0.5\nvex = [\"https://example.com/v1/vex.json\"]\n"),
            [
                "OSV",
                "CISA KEV",
                "EPSS",
                "conda-PyPI mapping",
                "extended policy",
                "VEX document"
            ]
        );
        assert_eq!(names("[hygiene]\n"), ["conda-PyPI mapping", "extended policy"]);
        assert_eq!(names("[licenses]\n"), ["PyPI wheels", "extended policy"]);
        assert_eq!(
            names("[freshness]\nmax-build-age-days = 30\n"),
            ["PyPI", "feedstock list", "feedstock outputs", "extended policy"]
        );
        assert_eq!(
            names("[freshness]\npypi = false\narchived = false\n"),
            ["extended policy"]
        );
    }

    #[test]
    fn caches_count_their_files_and_links_say_whether_they_are_pinned_and_cached() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://example.com/v1/base.toml";
        let extends = dir.path().join("extends");
        std::fs::create_dir_all(extends.join("nested")).unwrap();
        std::fs::write(extends.join(crate::fetch::sha256(url.as_bytes())), "").unwrap();
        std::fs::write(extends.join("nested").join("x"), "").unwrap();
        std::fs::write(dir.path().join("loose-file"), "").unwrap();
        let now = SystemTime::now() + Duration::from_secs(7200);
        let found = caches(dir.path(), now);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].0.as_str(), found[0].1), ("extends", 2));
        assert_eq!(found[0].2.map(ago), Some("2h".to_string()));
        assert!(caches(&dir.path().join("none"), now).is_empty());

        assert_eq!(link(url, Some(dir.path())), format!("{url} (pinned; cached)"));
        let main = "https://example.com/main/base.toml";
        assert_eq!(
            link(main, None),
            format!("{main} (not pinned: a tag, a commit or a sha256 makes it so; not cached)")
        );
        assert_eq!(link("base.toml", None), "base.toml (a local file)");
        let units: Vec<String> = [5, 600, 36_000, 864_000].map(|s| ago(Duration::from_secs(s))).into();
        assert_eq!(units, ["5s", "10m", "10h", "10d"]);
    }
}
