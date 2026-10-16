//! `manifest.*`: pixi.toml hygiene (#64). Writing a `[manifest]` table turns on `wildcard-spec` and `python-pinned`
//! (each can be set to false); `required-platforms` runs when its list is given (decided on #64). Findings point at the
//! manifest line.

use std::collections::BTreeSet;
use std::str::FromStr;

use rattler_conda_types::{ParseStrictness, Version, VersionSpec};

use crate::check::{File, Finding, Rule, Severity};
use crate::manifest::{Dependency, DependencyKind, Manifest};
use crate::policy::Policy;

/// Whether a conda spec lets Python move by no more than its patch version: the versions it accepts, sampled across
/// every minor from 2.0 to 4.30 and around every version the spec itself names, all share one minor (`3.12.*`,
/// `>=3.12,<3.13`, `3.12.5`).
pub fn python_pinned(text: &str) -> bool {
    let Ok(spec) = VersionSpec::from_str(text, ParseStrictness::Lenient) else {
        return false;
    };
    let mut samples: Vec<String> = Vec::new();
    for major in 2..=4 {
        for minor in 0..=30 {
            samples.extend([0, 1, 99].map(|patch| format!("{major}.{minor}.{patch}")));
        }
    }
    // Each version the spec names, and the next minor and major above it, so an open upper bound reaches a second
    // minor however high it starts.
    for token in text
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .map(|t| t.trim_matches('.'))
    {
        let parts: Vec<u64> = token.split('.').filter_map(|p| p.parse().ok()).collect();
        let (Some(&major), minor) = (parts.first(), parts.get(1).copied().unwrap_or(0)) else {
            continue;
        };
        samples.push(token.to_string());
        samples.push(format!("{major}.{}.0", minor + 1));
        samples.push(format!("{}.0.0", major + 1));
    }
    let minors: BTreeSet<(String, String)> = samples
        .iter()
        .filter_map(|sample| Version::from_str(sample).ok().map(|version| (sample, version)))
        .filter(|(_, version)| spec.matches(version))
        .map(|(sample, _)| {
            let mut parts = sample.split('.');
            (
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("0").to_string(),
            )
        })
        .collect();
    minors.len() == 1
}

/// The seconds in each unit a humantime duration may use, longest names first.
const UNITS: &[(&str, f64)] = &[
    ("nsec", 1e-9),
    ("ns", 1e-9),
    ("usec", 1e-6),
    ("us", 1e-6),
    ("msec", 1e-3),
    ("ms", 1e-3),
    ("seconds", 1.0),
    ("second", 1.0),
    ("secs", 1.0),
    ("sec", 1.0),
    ("s", 1.0),
    ("minutes", 60.0),
    ("minute", 60.0),
    ("mins", 60.0),
    ("min", 60.0),
    ("m", 60.0),
    ("hours", 3600.0),
    ("hour", 3600.0),
    ("hrs", 3600.0),
    ("hr", 3600.0),
    ("h", 3600.0),
    ("days", 86_400.0),
    ("day", 86_400.0),
    ("d", 86_400.0),
    ("weeks", 604_800.0),
    ("week", 604_800.0),
    ("w", 604_800.0),
    ("months", 2_630_016.0),
    ("month", 2_630_016.0),
    ("M", 2_630_016.0),
    ("years", 31_557_600.0),
    ("year", 31_557_600.0),
    ("y", 31_557_600.0),
];

/// A humantime duration (`7d`, `1h30m`, `2 weeks`) in seconds.
pub(crate) fn duration(text: &str) -> Option<f64> {
    let mut rest = text.trim();
    let mut total = 0.0;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let number: f64 = rest[..digits].parse().ok()?;
        rest = rest[digits..].trim_start();
        let (unit, seconds) = UNITS.iter().find(|(unit, _)| {
            rest.starts_with(unit) && !rest[unit.len()..].starts_with(|c: char| c.is_ascii_alphabetic())
        })?;
        total += number * seconds;
        rest = rest[unit.len()..].trim_start();
    }
    Some(total)
}

/// `YYYY-MM-DD` as days since 1970.
fn date_days(text: &str) -> Option<i64> {
    let mut parts = text.split('-').map(|part| part.parse::<u32>().ok());
    let (year, month, day) = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let date = crate::waivers::Date {
        year: i32::try_from(year).ok()?,
        month,
        day,
    };
    Some(date.days())
}

/// The cooldown pixi's `exclude-newer` `value` gives at `now` (seconds since 1970), in days: a duration's length, or
/// how long before now a date's or a timestamp's cutoff is. A date means the start of the next day, UTC, as pixi
/// reads it. `None` when it is none of the three.
pub fn cooldown_days(value: &str, now: i64) -> Option<f64> {
    let value = value.trim();
    if value.len() == 10 && value.as_bytes()[4] == b'-' {
        let cutoff = (date_days(value)? + 1) * 86_400;
        return Some((now - cutoff) as f64 / 86_400.0);
    }
    if value.len() >= 20 && matches!(value.as_bytes()[10], b'T' | b't' | b' ') {
        let days = date_days(&value[..10])?;
        let mut clock = value[11..19].split(':').map(|part| part.parse::<i64>().ok());
        let (h, m, s) = (clock.next()??, clock.next()??, clock.next()??);
        let zone = value[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
        let offset = match zone {
            "Z" | "z" => 0,
            zone if zone.len() == 6 => {
                let sign = if zone.starts_with('-') { -1 } else { 1 };
                sign * (zone[1..3].parse::<i64>().ok()? * 3600 + zone[4..6].parse::<i64>().ok()? * 60)
            }
            _ => return None,
        };
        let at = days * 86_400 + h * 3600 + m * 60 + s - offset;
        return Some((now - at) as f64 / 86_400.0);
    }
    duration(value).map(|seconds| seconds / 86_400.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    WildcardSpec,
    PythonPinned,
    RequiredPlatforms,
    ExcludeNewer,
}

struct ManifestRule {
    which: Which,
}

/// The four `manifest.*` rules.
pub fn rules() -> Vec<Box<dyn Rule>> {
    [
        Which::WildcardSpec,
        Which::PythonPinned,
        Which::RequiredPlatforms,
        Which::ExcludeNewer,
    ]
    .into_iter()
    .map(|which| Box::new(ManifestRule { which }) as Box<dyn Rule>)
    .collect()
}

impl ManifestRule {
    fn finding(&self, manifest: &Manifest, package: Option<&str>, line: u32, message: String, help: &str) -> Finding {
        Finding {
            rule: self.id(),
            severity: Severity::Error,
            package: package.map(str::to_string),
            version: None,
            environment: String::new(),
            platform: String::new(),
            file: if manifest.pyproject {
                File::Pyproject
            } else {
                File::Manifest
            },
            line: Some(line),
            message,
            help: Some(help.into()),
            advisory: Vec::new(),
        }
    }

    fn dependency(&self, manifest: &Manifest, dep: &Dependency, message: String, help: &str) -> Finding {
        self.finding(manifest, Some(&dep.name), dep.line, message, help)
    }
}

impl Rule for ManifestRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::WildcardSpec => "manifest.wildcard-spec",
            Which::PythonPinned => "manifest.python-pinned",
            Which::RequiredPlatforms => "manifest.required-platforms",
            Which::ExcludeNewer => "manifest.exclude-newer",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::WildcardSpec => "No dependency is given as `*`",
            Which::PythonPinned => "Python is constrained to one minor version or narrower",
            Which::RequiredPlatforms => "The workspace lists every platform the policy requires",
            Which::ExcludeNewer => "exclude-newer keeps packages out for at least min-exclude-newer-days",
        }
    }

    fn check_manifest(&self, policy: &Policy, manifest: &Manifest) -> Vec<Finding> {
        let Some(settings) = &policy.manifest else {
            return Vec::new();
        };
        match self.which {
            Which::WildcardSpec if settings.wildcard_spec.unwrap_or(true) => manifest
                .dependencies
                .iter()
                .filter(|dep| dep.spec.as_deref().map(str::trim) == Some("*"))
                .map(|dep| {
                    self.dependency(
                        manifest,
                        dep,
                        format!("is given as \"*\" in [{}]", dep.table),
                        "give it a version range, for example the one `pixi add` writes",
                    )
                })
                .collect(),
            Which::PythonPinned if settings.python_pinned.unwrap_or(true) => manifest
                .dependencies
                .iter()
                .filter(|dep| dep.kind == DependencyKind::Conda && dep.name.eq_ignore_ascii_case("python"))
                .filter(|dep| !dep.spec.as_deref().is_some_and(python_pinned))
                .map(|dep| {
                    let spec = dep.spec.as_deref().unwrap_or("no version");
                    self.dependency(
                        manifest,
                        dep,
                        format!("is not pinned to one minor version in [{}] ({spec})", dep.table),
                        "pin the minor version, for example python = \"3.12.*\"",
                    )
                })
                .collect(),
            Which::RequiredPlatforms => {
                let Some(required) = &settings.required_platforms else {
                    return Vec::new();
                };
                let (listed, line) = manifest.platforms.clone().unwrap_or((Vec::new(), 1));
                required
                    .iter()
                    .filter(|platform| !listed.contains(platform))
                    .map(|platform| {
                        self.finding(
                            manifest,
                            None,
                            line,
                            format!(
                                "platform {platform} is required by the policy but not in the workspace's platforms"
                            ),
                            "add it to platforms in [workspace] and run `pixi lock`",
                        )
                    })
                    .collect()
            }
            Which::ExcludeNewer => {
                let Some(min) = settings.min_exclude_newer_days else {
                    return Vec::new();
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
                self.exclude_newer(manifest, min, now)
            }
            _ => Vec::new(),
        }
    }
}

impl ManifestRule {
    /// The `manifest.exclude-newer` findings for a minimum of `min` days at `now`.
    fn exclude_newer(&self, manifest: &Manifest, min: u32, now: i64) -> Vec<Finding> {
        let wanted = format!("exclude-newer = \"{min}d\"");
        let judge = |value: &str| match cooldown_days(value, now) {
            None => Some(format!(
                "is {value:?}, which pixi-policy cannot read as a duration, a date or a timestamp"
            )),
            Some(days) if days < f64::from(min) => Some(format!(
                "is {value:?}, a cooldown of {}, less than min-exclude-newer-days ({min})",
                shown(days)
            )),
            Some(_) => None,
        };
        let mut out = Vec::new();
        let place = &manifest.exclude_newer;
        match &place.workspace {
            None => out.push(self.finding(
                manifest,
                None,
                place.table_line,
                "the workspace sets no exclude-newer, so a package published minutes ago can be locked".into(),
                &format!("set {wanted} in the workspace table"),
            )),
            Some((value, line)) => {
                if let Some(problem) = judge(value) {
                    out.push(self.finding(
                        manifest,
                        None,
                        *line,
                        format!("the workspace's exclude-newer {problem}"),
                        &format!("set {wanted} in the workspace table"),
                    ));
                }
            }
        }
        for (table, package, value, line) in &place.overrides {
            if let Some(problem) = judge(value) {
                out.push(self.finding(
                    manifest,
                    Some(package),
                    *line,
                    format!("its exclude-newer in [{table}] {problem}"),
                    "remove the override, or waive it for this package with the reason it needs one",
                ));
            }
        }
        out
    }
}

/// `3 days`, `1.5 days`, `-2 days` for a cutoff in the future.
fn shown(days: f64) -> String {
    let rounded = (days * 10.0).round() / 10.0;
    match rounded {
        1.0 => "1 day".to_string(),
        whole if whole.fract() == 0.0 => format!("{} days", whole as i64),
        _ => format!("{rounded} days"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cooldown_is_read_from_a_duration_a_date_or_a_timestamp() {
        let now = (crate::waivers::Date {
            year: 2026,
            month: 10,
            day: 15,
        })
        .days()
            * 86_400
            + 12 * 3600;
        let days = |value: &str| cooldown_days(value, now);
        assert_eq!(days("7d"), Some(7.0));
        assert_eq!(days("1w"), Some(7.0));
        assert_eq!(days("1h30m"), Some(1.5 / 24.0));
        assert_eq!(days("2 weeks"), Some(14.0));
        assert_eq!(days("0d"), Some(0.0));
        assert_eq!(days("2026-10-01"), Some(13.5), "the cutoff is the start of 10-02");
        assert_eq!(days("2026-10-14T12:00:00Z"), Some(1.0));
        assert_eq!(days("2026-10-14T14:00:00+02:00"), Some(1.0));
        assert_eq!(days("2026-10-14T12:00:00.5Z"), Some(1.0));
        for bad in ["", "soon", "7 fortnights", "2026-13-01", "2026-10-14T12:00:00", "d7"] {
            assert_eq!(days(bad), None, "{bad}");
        }
        assert_eq!(shown(1.5), "1.5 days");
        assert_eq!(shown(-2.0), "-2 days");
        assert_eq!(shown(1.0), "1 day");
    }

    #[test]
    fn exclude_newer_and_each_override_must_keep_the_cooldown() {
        let now = (crate::waivers::Date {
            year: 2026,
            month: 10,
            day: 15,
        })
        .days()
            * 86_400;
        let rule = ManifestRule {
            which: Which::ExcludeNewer,
        };
        let found = |text: &str| -> Vec<(Option<String>, u32, String)> {
            let manifest = Manifest::parse(text, false).unwrap();
            rule.exclude_newer(&manifest, 7, now)
                .into_iter()
                .map(|f| (f.package, f.line.unwrap(), f.message))
                .collect()
        };
        let missing = found("[workspace]\nplatforms = []\n");
        assert_eq!(
            missing,
            [(
                None,
                1,
                "the workspace sets no exclude-newer, so a package published minutes ago can be locked".to_string()
            )]
        );
        assert!(found("[workspace]\nexclude-newer = \"7d\"\n").is_empty());
        assert!(
            found("[workspace]\nexclude-newer = \"2026-01-01\"\n").is_empty(),
            "an old date"
        );
        let short = found("[workspace]\nexclude-newer = \"3d\"\n");
        assert_eq!(
            short[0].2,
            "the workspace's exclude-newer is \"3d\", a cooldown of 3 days, less than min-exclude-newer-days (7)"
        );
        let recent = found("[workspace]\nexclude-newer = \"2026-10-13\"\n");
        assert!(recent[0].2.contains("a cooldown of 1 day"), "{recent:?}");
        let overrides = found(
            "[workspace]\nexclude-newer = \"14d\"\n\n[exclude-newer]\npytorch-cpu = \"0d\"\nopenssl = \"30d\"\n\n\
             [pypi-exclude-newer]\ntorch = \"1d\"\n",
        );
        assert_eq!(
            overrides,
            [
                (Some("pytorch-cpu".to_string()), 5, "its exclude-newer in [exclude-newer] is \"0d\", a cooldown of 0 days, less than min-exclude-newer-days (7)".to_string()),
                (Some("torch".to_string()), 9, "its exclude-newer in [pypi-exclude-newer] is \"1d\", a cooldown of 1 day, less than min-exclude-newer-days (7)".to_string()),
            ]
        );
        let odd = found("[workspace]\nexclude-newer = \"whenever\"\n");
        assert!(odd[0].2.contains("cannot read as a duration"), "{odd:?}");
        let pyproject = Manifest::parse(
            "[project]\nname = \"x\"\n\n[tool.pixi.workspace]\nplatforms = []\n",
            true,
        )
        .unwrap();
        assert_eq!(rule.exclude_newer(&pyproject, 7, now)[0].line, Some(4));
    }

    fn fixture(name: &str) -> Manifest {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifest")
            .join(name);
        Manifest::load(&dir.join("pixi.toml")).unwrap()
    }

    fn found(policy: &str, manifest: &Manifest) -> Vec<(&'static str, Option<String>, Option<u32>)> {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        rules()
            .iter()
            .flat_map(|rule| rule.check_manifest(&policy, manifest))
            .map(|f| (f.rule, f.package, f.line))
            .collect()
    }

    const ALL: &str = "[manifest]\nrequired-platforms = [\"linux-64\", \"osx-arm64\", \"win-64\"]\n";

    #[test]
    fn the_passing_fixture_passes_every_rule() {
        assert!(found(ALL, &fixture("pass")).is_empty());
    }

    #[test]
    fn the_failing_fixture_fails_each_rule_at_its_line() {
        let got = found(ALL, &fixture("fail"));
        assert_eq!(
            got,
            [
                ("manifest.wildcard-spec", Some("numpy".to_string()), Some(8)),
                ("manifest.wildcard-spec", Some("requests".to_string()), Some(11)),
                ("manifest.wildcard-spec", Some("ruff".to_string()), Some(14)),
                ("manifest.python-pinned", Some("python".to_string()), Some(7)),
                ("manifest.required-platforms", None, Some(4)),
                ("manifest.required-platforms", None, Some(4)),
            ]
        );
    }

    #[test]
    fn rules_follow_the_settings() {
        let fail = fixture("fail");
        assert!(found("", &fail).is_empty(), "no [manifest], no findings");
        let on = found("[manifest]\n", &fail);
        assert_eq!(
            on.len(),
            4,
            "wildcard-spec and python-pinned are on once [manifest] exists: {on:?}"
        );
        let off = found("[manifest]\nwildcard-spec = false\npython-pinned = false\n", &fail);
        assert!(off.is_empty(), "{off:?}");
        assert!(Policy::parse("[manifest]\nwildcard = true\n", "p.toml").is_err());
    }

    #[test]
    fn python_is_pinned_to_one_minor_or_narrower() {
        for spec in [
            "3.12.*",
            ">=3.12,<3.13",
            "3.12.5",
            "==3.12.5",
            "3.12",
            "~=3.12.0",
            ">=3.12.1,<3.12.4",
        ] {
            assert!(python_pinned(spec), "{spec}");
        }
        for spec in ["*", ">=3.10", "3.*", ">=3.11,<3.13", "<4", "not a spec !!", ">=9"] {
            assert!(!python_pinned(spec), "{spec}");
        }
    }

    #[test]
    fn findings_explain_and_name_the_file() {
        let policy = Policy::parse("[manifest]\nrequired-platforms = [\"win-64\"]\n", "p.toml").unwrap();
        let fail = fixture("fail");
        let all: Vec<Finding> = rules().iter().flat_map(|r| r.check_manifest(&policy, &fail)).collect();
        assert_eq!(all[0].message, "is given as \"*\" in [dependencies]");
        assert!(
            all.iter()
                .any(|f| f.message == "is not pinned to one minor version in [dependencies] (>=3.10)")
        );
        assert!(all.iter().any(|f| f.message.starts_with("platform win-64 is required")));
        assert!(
            all.iter()
                .all(|f| f.file == File::Manifest && f.severity == Severity::Error)
        );
        let pyproject = Manifest::parse("[tool.pixi.dependencies]\npython = \"*\"\n", true).unwrap();
        let findings: Vec<Finding> = rules()
            .iter()
            .flat_map(|r| r.check_manifest(&policy, &pyproject))
            .collect();
        assert!(findings.iter().all(|f| f.file == File::Pyproject));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "manifest.required-platforms" && f.line == Some(1)),
            "no platforms: line 1"
        );
        let summaries: Vec<&str> = rules().iter().map(|r| r.summary()).collect();
        assert!(summaries.iter().all(|s| !s.is_empty()));
        let unpinned = Manifest::parse("[dependencies]\npython = { channel = \"conda-forge\" }\n", false).unwrap();
        let findings: Vec<Finding> = rules()
            .iter()
            .flat_map(|r| r.check_manifest(&policy, &unpinned))
            .collect();
        assert!(findings.iter().any(|f| f.message.ends_with("(no version)")));
    }
}
