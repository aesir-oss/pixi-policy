//! `licenses.*`: allow, review and deny lists of SPDX licenses (#63).
//!
//! The verdict is the shared crate's (`crate::license_policy`, #59), the one pixi-sbom's license gate gives: `deny`
//! and `allow` go to it exactly as the gate's `--deny-license` and `--allow-license` do. `review` licenses count as
//! allowed and are reported as warnings. Patterns with `*` are expanded against the SPDX license list into plain
//! identifiers first, so the verdict never sees a pattern. Licenses come from pixi.lock, which records them for conda
//! packages, and for PyPI wheels from pypi.org from the wheel's METADATA ([`crate::wheel`], #51).

use std::sync::Arc;

use crate::license::{self, License};
use crate::license_policy::{Lists, Reason};
use crate::lockfile::{Fact, Facts, Kind};
use crate::wheel::{self, Answer};

use crate::check::{File, Finding, Rule, Severity};
use crate::policy::{Licenses, Policy, Unknown};

/// Expand `entries`: an identifier as given, a pattern with `*` into every SPDX identifier it matches (ignoring case)
/// that the shared verdict accepts as a licensee.
pub fn expand(entries: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.trim();
        if !entry.contains('*') {
            out.push(entry.to_string());
            continue;
        }
        let matched: Vec<String> = spdx::identifiers::LICENSES
            .iter()
            .map(|license| license.name)
            .filter(|name| glob(&entry.to_ascii_lowercase(), &name.to_ascii_lowercase()))
            .filter(|name| Lists::new(&[(*name).to_string()], &[]).is_ok())
            .map(str::to_string)
            .collect();
        if matched.is_empty() {
            return Err(format!("{entry:?} matches no SPDX license identifier"));
        }
        out.extend(matched);
    }
    Ok(out)
}

/// `*` matches any run of characters; everything else matches itself.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

/// `[licenses]`, ready to evaluate.
#[derive(Debug)]
pub struct Compiled {
    /// `allow` (with `review`, when `allow` is given) and `deny`: the gate's verdict.
    gate: Lists,
    /// `review` as a deny list: denied here means the package needs a review license.
    review: Lists,
    unknown: Unknown,
    ambiguous: Unknown,
}

impl Compiled {
    /// Expand and parse the lists, or say which entry is wrong.
    pub fn new(licenses: &Licenses) -> Result<Self, String> {
        let deny = expand(&licenses.deny)?;
        let review = expand(&licenses.review)?;
        let mut allow = expand(&licenses.allow)?;
        if !allow.is_empty() {
            allow.extend(review.iter().cloned());
        }
        let invalid = |err: crate::license_policy::LicenseeError| {
            format!("{:?} is not an SPDX license identifier ({})", err.text, err.reason)
        };
        Ok(Self {
            gate: Lists::new(&allow, &deny).map_err(invalid)?,
            review: Lists::new(&[], &review).map_err(invalid)?,
            unknown: licenses.unknown,
            ambiguous: licenses.ambiguous,
        })
    }

    /// What the policy says about `fact`'s license, as pixi.lock gives it.
    pub fn verdict(&self, fact: &Fact) -> Option<Verdict> {
        self.verdict_of(&declared(fact, None))
    }

    /// What the policy says about a license as `declared`.
    fn verdict_of(&self, declared: &Declared) -> Option<Verdict> {
        if declared.ambiguous.is_some() {
            return Some(Verdict::Ambiguous);
        }
        let Some(raw) = declared.raw.as_deref() else {
            return Some(Verdict::Unknown(Reason::Missing));
        };
        let expression = match license::normalize(raw) {
            License::Expression(expression) => expression,
            License::Text(_) => return Some(Verdict::Unknown(Reason::NotSpdx)),
            License::Ambiguous(_) => return Some(Verdict::Ambiguous),
        };
        if let Some(reason) = self.gate.evaluate(&expression) {
            return Some(Verdict::Fails(reason, expression));
        }
        (self.review.evaluate(&expression) == Some(Reason::Denied)).then_some(Verdict::Review(expression))
    }
}

/// The policy's answer for one package, when it has something to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The shared verdict: [`Reason::Denied`] or [`Reason::NotAllowed`], with the expression.
    Fails(Reason, String),
    /// Acceptable once reviewed.
    Review(String),
    /// [`Reason::Missing`] or [`Reason::NotSpdx`].
    Unknown(Reason),
    /// A name that could be more than one SPDX license.
    Ambiguous,
}

/// A package's license as the rules see it: pixi.lock's, or for a PyPI wheel its METADATA's.
#[derive(Debug, Default)]
struct Declared {
    raw: Option<String>,
    /// Where `raw` comes from: `pixi.lock` or `its METADATA`.
    source: &'static str,
    /// Why there is none, when the wheel says why.
    note: Option<String>,
    /// Why it could be more than one license, when its METADATA's classifiers say so.
    ambiguous: Option<String>,
}

fn declared(fact: &Fact, wheels: Option<&wheel::Data>) -> Declared {
    if let Some(raw) = fact.license.as_deref().map(str::trim).filter(|raw| !raw.is_empty()) {
        return Declared {
            raw: Some(raw.to_string()),
            source: "pixi.lock",
            ..Declared::default()
        };
    }
    let mut out = Declared {
        source: "its METADATA",
        ..Declared::default()
    };
    match wheels.and_then(|data| data.for_package(fact)) {
        Some(Answer::Declared(raw)) => out.raw = Some(raw.trim().to_string()),
        Some(Answer::Ambiguous(why)) => out.ambiguous = Some(why.clone()),
        Some(Answer::Nothing) => out.note = Some("its METADATA states no license".into()),
        Some(Answer::NotRead(why)) => out.note = Some(why.clone()),
        Some(Answer::Failed(why)) => out.note = Some(format!("its METADATA could not be read: {why}")),
        None => {}
    }
    out
}

/// How a finding names `expression`: with what its source says when it was spelt otherwise (#7).
fn named(expression: &str, declared: &Declared) -> String {
    match declared.raw.as_deref() {
        Some(raw) if raw != expression => format!("{expression} ({} says {raw:?})", declared.source),
        _ => expression.to_string(),
    }
}

fn severity(setting: Unknown) -> Option<Severity> {
    match setting {
        Unknown::Allow => None,
        Unknown::Warn => Some(Severity::Warning),
        Unknown::Error => Some(Severity::Error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Deny,
    Review,
    NotAllowed,
    Unknown,
    Ambiguous,
}

struct LicenseRule {
    which: Which,
    wheels: Option<Arc<wheel::Data>>,
}

/// The five `licenses.*` rules, PyPI packages judged by `wheels`, their wheels' licenses.
pub fn rules(wheels: Option<Arc<wheel::Data>>) -> Vec<Box<dyn Rule>> {
    [
        Which::Deny,
        Which::Review,
        Which::NotAllowed,
        Which::Unknown,
        Which::Ambiguous,
    ]
    .into_iter()
    .map(|which| {
        Box::new(LicenseRule {
            which,
            wheels: wheels.clone(),
        }) as Box<dyn Rule>
    })
    .collect()
}

impl LicenseRule {
    /// The finding's severity, message and help for `verdict`, when it is this rule's.
    fn speak(
        &self,
        verdict: Verdict,
        compiled: &Compiled,
        fact: &Fact,
        declared: &Declared,
    ) -> Option<(Severity, String, String)> {
        match (self.which, verdict) {
            (Which::Ambiguous, Verdict::Ambiguous) => Some((
                severity(compiled.ambiguous)?,
                match &declared.ambiguous {
                    Some(why) => format!("its METADATA gives {why}, which could be more than one SPDX license"),
                    None => format!(
                        "license {:?} could be more than one SPDX license",
                        declared.raw.as_deref().unwrap_or("")
                    ),
                },
                "find the license the package ships and waive this with it as the reason, or ask its maintainers to \
                 state an SPDX license; [licenses] ambiguous sets what this gets"
                    .into(),
            )),
            (Which::Deny, Verdict::Fails(Reason::Denied, expression)) => Some((
                Severity::Error,
                format!(
                    "license {} cannot be satisfied without a denied license",
                    named(&expression, declared)
                ),
                "replace the package, or take the license off [licenses] deny".into(),
            )),
            (Which::NotAllowed, Verdict::Fails(Reason::NotAllowed, expression)) => Some((
                Severity::Error,
                format!(
                    "license {} cannot be satisfied with the allowed licenses",
                    named(&expression, declared)
                ),
                "replace the package, or add the license to [licenses] allow".into(),
            )),
            (Which::Review, Verdict::Review(expression)) => Some((
                Severity::Warning,
                format!("license {} needs a review", named(&expression, declared)),
                "have the license reviewed; once approved, move it from [licenses] review to allow".into(),
            )),
            (Which::Unknown, Verdict::Unknown(reason)) => {
                let severity = severity(compiled.unknown)?;
                let raw = declared.raw.as_deref().unwrap_or("");
                let from = match declared.source {
                    "pixi.lock" => String::new(),
                    source => format!(" in {source}"),
                };
                let message = match (reason, fact.kind, &declared.note) {
                    (Reason::Missing, Kind::Pypi, Some(note)) => format!("has no license pixi-policy can read: {note}"),
                    (Reason::Missing, Kind::Pypi, None) => {
                        "has no license in pixi.lock (it never records PyPI licenses)".into()
                    }
                    (Reason::Missing, ..) => "declares no license".into(),
                    _ => match license::rejection_reason(raw) {
                        Some(why) => format!("license {raw:?}{from} is not an SPDX expression ({why})"),
                        None => format!("license {raw:?}{from} is not an SPDX expression"),
                    },
                };
                let help = if fact.kind == Kind::Pypi {
                    "find the license the package ships and waive this with it as the reason, or set [licenses] \
                     unknown = \"allow\" to stop these"
                } else {
                    "ask the package's maintainers for an SPDX license, or set [licenses] unknown to \"warn\" or \"allow\""
                };
                Some((severity, message, help.into()))
            }
            _ => None,
        }
    }
}

impl Rule for LicenseRule {
    fn id(&self) -> &'static str {
        match self.which {
            Which::Deny => "licenses.deny",
            Which::Review => "licenses.review",
            Which::NotAllowed => "licenses.not-allowed",
            Which::Unknown => "licenses.unknown",
            Which::Ambiguous => "licenses.ambiguous",
        }
    }

    fn summary(&self) -> &'static str {
        match self.which {
            Which::Deny => "No package needs a license the policy denies",
            Which::Review => "Packages that need a license under review are reported for it",
            Which::NotAllowed => "Every package can be used under the licenses the policy allows",
            Which::Unknown => "Every package declares an SPDX license",
            Which::Ambiguous => "No package's license is a name that could be more than one SPDX license",
        }
    }

    fn check(&self, policy: &Policy, facts: &Facts) -> Vec<Finding> {
        let Some(compiled) = policy.licenses.as_ref().and_then(|l| Compiled::new(l).ok()) else {
            return Vec::new();
        };
        facts
            .packages
            .iter()
            .filter_map(|fact| {
                let declared = declared(fact, self.wheels.as_deref());
                let (severity, message, help) =
                    self.speak(compiled.verdict_of(&declared)?, &compiled, fact, &declared)?;
                Some(Finding {
                    rule: self.id(),
                    severity,
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

    fn fact(name: &str, license: Option<&str>, kind: Kind) -> Fact {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sources/pixi.lock");
        let lock = crate::check::load_lockfile(&path).unwrap();
        let mut fact = crate::lockfile::read(&lock, "default", Some("linux-64"))
            .unwrap()
            .packages
            .remove(0);
        fact.name = name.into();
        fact.license = license.map(str::to_string);
        fact.kind = kind;
        fact
    }

    fn findings(policy: &str, packages: Vec<Fact>) -> Vec<(&'static str, Severity, String)> {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages,
        };
        rules(None)
            .iter()
            .flat_map(|rule| rule.check(&policy, &facts))
            .map(|f| (f.rule, f.severity, f.package.unwrap()))
            .collect()
    }

    /// The shared verdict table (#59) through this rule: the verdict pixi-sbom's gate gives, case by case.
    #[test]
    fn the_shared_verdict_table_gives_the_same_verdicts_through_the_rule() {
        for case in crate::license_policy::cases::CASES {
            let list = |items: &[&str]| items.iter().map(|i| format!("{i:?}")).collect::<Vec<_>>().join(", ");
            let policy = format!(
                "[licenses]\nallow = [{}]\ndeny = [{}]\nunknown = \"allow\"\n",
                list(case.allow),
                list(case.deny)
            );
            let got = findings(&policy, vec![fact("pkg", Some(case.expression), Kind::CondaBinary)]);
            let reason = got.first().map(|(rule, _, _)| match *rule {
                "licenses.deny" => Reason::Denied,
                "licenses.not-allowed" => Reason::NotAllowed,
                other => panic!("{other}"),
            });
            assert!(got.len() <= 1, "{got:?}");
            assert_eq!(reason, case.expected, "{}: {}", case.expression, case.why);
        }
    }

    #[test]
    fn review_licenses_are_warnings_and_count_as_allowed() {
        let policy = "[licenses]\nallow = [\"MIT\"]\nreview = [\"LGPL-*\"]\ndeny = [\"GPL-3.0-*\", \"AGPL-*\"]\n";
        let got = findings(
            policy,
            vec![
                fact("ok", Some("MIT"), Kind::CondaBinary),
                fact("lgpl", Some("LGPL-2.1-or-later"), Kind::CondaBinary),
                fact("gpl", Some("GPL-3.0-only"), Kind::CondaBinary),
                fact("agpl", Some("AGPL-3.0-or-later"), Kind::CondaBinary),
                fact("bsd", Some("BSD-3-Clause"), Kind::CondaBinary),
                fact("either", Some("MIT OR GPL-3.0-only"), Kind::CondaBinary),
            ],
        );
        assert_eq!(
            got,
            [
                ("licenses.deny", Severity::Error, "gpl".to_string()),
                ("licenses.deny", Severity::Error, "agpl".to_string()),
                ("licenses.review", Severity::Warning, "lgpl".to_string()),
                ("licenses.not-allowed", Severity::Error, "bsd".to_string()),
            ]
        );
    }

    #[test]
    fn unknown_licenses_warn_by_default_and_follow_the_setting() {
        let packages = || {
            vec![
                fact("none", None, Kind::CondaBinary),
                fact("blank", Some("  "), Kind::CondaBinary),
                fact("text", Some("Proprietary"), Kind::CondaBinary),
                fact("wheel", None, Kind::Pypi),
            ]
        };
        let warn = findings("[licenses]\n", packages());
        assert_eq!(warn.len(), 4);
        assert!(
            warn.iter()
                .all(|(rule, severity, _)| *rule == "licenses.unknown" && *severity == Severity::Warning)
        );
        let error = findings("[licenses]\nunknown = \"error\"\n", packages());
        assert!(error.iter().all(|(_, severity, _)| *severity == Severity::Error));
        assert!(findings("[licenses]\nunknown = \"allow\"\n", packages()).is_empty());
        assert!(findings("", packages()).is_empty(), "no [licenses], no findings");

        let policy = Policy::parse("[licenses]\n", "p.toml").unwrap();
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages: packages(),
        };
        let unknown = LicenseRule {
            which: Which::Unknown,
            wheels: None,
        };
        let messages: Vec<String> = unknown.check(&policy, &facts).into_iter().map(|f| f.message).collect();
        assert_eq!(messages[0], "declares no license");
        assert!(
            messages[2].starts_with("license \"Proprietary\" is not an SPDX expression"),
            "{}",
            messages[2]
        );
        assert_eq!(
            messages[3],
            "has no license in pixi.lock (it never records PyPI licenses)"
        );
    }

    #[test]
    fn a_pypi_package_is_judged_by_its_wheel() {
        let wheel = |name: &str, sha: &str| {
            let mut fact = fact(name, None, Kind::Pypi);
            fact.sha256 = Some(sha.into());
            fact
        };
        let mut data = wheel::Data::default();
        for (sha, answer) in [
            ("1", Answer::Declared("GPL-3.0-only".into())),
            ("2", Answer::Declared("BSD 3-Clause".into())),
            (
                "3",
                Answer::Ambiguous("2 license classifiers (MIT License; BSD License)".into()),
            ),
            ("4", Answer::Nothing),
            (
                "5",
                Answer::NotRead("it is a source distribution, whose license pixi-policy does not read".into()),
            ),
            ("6", Answer::Failed("timed out".into())),
        ] {
            data.insert(sha, answer);
        }
        let data = Some(Arc::new(data));
        let packages = ["gpl", "bsd", "both", "none", "sdist", "down", "unlooked"]
            .iter()
            .enumerate()
            .map(|(i, name)| wheel(name, &(i + 1).to_string()))
            .collect::<Vec<_>>();
        let policy = Policy::parse(
            "[licenses]\nreview = [\"BSD-3-Clause\"]\ndeny = [\"GPL-3.0-only\"]\n",
            "p.toml",
        )
        .unwrap();
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages,
        };
        let found: Vec<(&str, String, String)> = rules(data)
            .iter()
            .flat_map(|rule| rule.check(&policy, &facts))
            .map(|f| (f.rule, f.package.unwrap(), f.message))
            .collect();
        let message = |name: &str| {
            found
                .iter()
                .find(|(_, package, _)| package == name)
                .map(|(rule, _, message)| format!("{rule}: {message}"))
                .unwrap()
        };
        assert_eq!(
            message("gpl"),
            "licenses.deny: license GPL-3.0-only cannot be satisfied without a denied license"
        );
        assert_eq!(
            message("bsd"),
            "licenses.review: license BSD-3-Clause (its METADATA says \"BSD 3-Clause\") needs a review"
        );
        assert_eq!(
            message("both"),
            "licenses.ambiguous: its METADATA gives 2 license classifiers (MIT License; BSD License), which could be \
             more than one SPDX license"
        );
        assert_eq!(
            message("none"),
            "licenses.unknown: has no license pixi-policy can read: its METADATA states no license"
        );
        assert!(message("sdist").ends_with("source distribution, whose license pixi-policy does not read"));
        assert!(message("down").ends_with("its METADATA could not be read: timed out"));
        assert_eq!(
            message("unlooked"),
            "licenses.unknown: has no license in pixi.lock (it never records PyPI licenses)"
        );
    }

    #[test]
    fn patterns_expand_against_the_spdx_list() {
        let lgpl = expand(&["lgpl-2.1*".to_string()]).unwrap();
        assert!(
            lgpl.contains(&"LGPL-2.1-only".to_string()) && lgpl.contains(&"LGPL-2.1-or-later".to_string()),
            "{lgpl:?}"
        );
        assert!(lgpl.iter().all(|id| id.starts_with("LGPL-2.1")));
        assert_eq!(expand(&["MIT".to_string()]).unwrap(), ["MIT"]);
        assert!(glob("x*y*z", "x11y22z") && !glob("x*y*z", "x11z") && glob("*", "") && !glob("pq*qp", "pqp"));
        let err = Policy::parse("[licenses]\ndeny = [\"NOPE-*\"]\n", "p.toml").unwrap_err();
        assert!(err.to_string().contains("matches no SPDX license identifier"), "{err}");
        let err = Policy::parse("[licenses]\nallow = [\"not a license!!\"]\n", "p.toml").unwrap_err();
        assert!(err.to_string().contains("is not an SPDX license identifier"), "{err}");
        assert!(Policy::parse("[licenses]\nunknown = \"maybe\"\n", "p.toml").is_err());
    }

    #[test]
    fn an_ambiguous_license_is_its_own_finding_and_a_respelt_one_shows_what_the_lock_says() {
        let packages = || {
            vec![
                fact("bsd", Some("BSD"), Kind::CondaBinary),
                fact("apache", Some("Apache"), Kind::CondaBinary),
                fact("bsd3", Some("BSD 3-Clause"), Kind::CondaBinary),
                fact("psf", Some("PSF"), Kind::CondaBinary),
            ]
        };
        let found = findings("[licenses]\nallow = [\"BSD-3-Clause\"]\n", packages());
        assert_eq!(
            found,
            [
                ("licenses.not-allowed", Severity::Error, "psf".to_string()),
                ("licenses.ambiguous", Severity::Warning, "bsd".to_string()),
                ("licenses.ambiguous", Severity::Warning, "apache".to_string()),
            ]
        );
        let error = findings("[licenses]\nambiguous = \"error\"\n", packages());
        assert!(
            error
                .iter()
                .all(|f| f.0 == "licenses.ambiguous" && f.1 == Severity::Error),
            "{error:?}"
        );
        assert!(findings("[licenses]\nambiguous = \"allow\"\n", packages()).is_empty());

        let policy = Policy::parse("[licenses]\nreview = [\"PSF-2.0\"]\n", "p.toml").unwrap();
        let facts = Facts {
            environment: "default".into(),
            platform: "linux-64".into(),
            packages: packages(),
        };
        let messages: Vec<String> = rules(None)
            .iter()
            .flat_map(|rule| rule.check(&policy, &facts))
            .map(|f| f.message)
            .collect();
        assert!(
            messages.contains(&"license PSF-2.0 (pixi.lock says \"PSF\") needs a review".to_string()),
            "{messages:?}"
        );
        assert!(
            messages.contains(&"license \"Apache\" could be more than one SPDX license".to_string()),
            "{messages:?}"
        );
    }

    #[test]
    fn every_rule_has_an_id_and_a_summary() {
        let ids: Vec<&str> = rules(None).iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            [
                "licenses.deny",
                "licenses.review",
                "licenses.not-allowed",
                "licenses.unknown",
                "licenses.ambiguous"
            ]
        );
        assert!(rules(None).iter().all(|r| !r.summary().is_empty()));
    }
}
