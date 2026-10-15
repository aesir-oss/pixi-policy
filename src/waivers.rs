//! Waivers that expire (#66): an exception for one rule and one package, with a reason and an `expires` date.
//!
//! A waived finding is still reported, as waived, and does not fail the check. After `expires` it fails again and the
//! waiver is reported as expired; a waiver that matches nothing is reported as unused, and one that runs further than
//! `max-waiver-days` (default 365, decided on #66) is reported as too long. All three are warnings about the policy
//! file, at the waiver's line.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::check::{File, Finding, Outcome, Severity, Waived};
use crate::policy::{Policy, Waiver};

/// The findings about waivers, with their summaries: not rules a policy turns on, so not in the rule list, but
/// explained and listed in SARIF like one.
pub const RULES: [(&str, &str); 3] = [
    (
        "waivers.expired",
        "A waiver has expired, and what it waived fails again",
    ),
    ("waivers.unused", "A waiver matches no finding"),
    ("waivers.too-long", "A waiver runs further out than max-waiver-days"),
];

/// The default `max-waiver-days`.
pub const MAX_WAIVER_DAYS: u32 = 365;

/// A calendar date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl Date {
    /// A TOML value that is a date and nothing more (no time, no offset).
    pub fn from_toml(value: &toml::value::Datetime) -> Option<Self> {
        match (value.date, value.time, value.offset) {
            (Some(date), None, None) => Some(Self {
                year: i32::from(date.year),
                month: u32::from(date.month),
                day: u32::from(date.day),
            }),
            _ => None,
        }
    }

    /// Days since 1970-01-01 (Howard Hinnant's days_from_civil).
    pub fn days(self) -> i64 {
        let year = i64::from(self.year) - i64::from(self.month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let month = i64::from(self.month);
        let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The date `days` after 1970-01-01 (civil_from_days).
    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z - era * 146_097;
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let mp = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = (year_of_era + era * 400 + i64::from(month <= 2)) as i32;
        Self { year, month, day }
    }

    /// Today, in UTC.
    pub fn today() -> Self {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        Self::from_days(i64::try_from(seconds / 86_400).unwrap_or(0))
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn covers(waiver: &Waiver, finding: &Finding) -> bool {
    let same = |wanted: &Option<String>, have: Option<&str>| wanted.as_deref().is_none_or(|w| Some(w) == have);
    waiver.rule == finding.rule
        && finding
            .package
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(&waiver.package))
        && same(&waiver.version, finding.version.as_deref())
        && same(&waiver.environment, Some(&finding.environment))
        && same(&waiver.platform, Some(&finding.platform))
        && waiver
            .advisory
            .as_deref()
            .is_none_or(|wanted| finding.advisory.iter().any(|name| name.eq_ignore_ascii_case(wanted)))
}

fn about(waiver: &Waiver, rule: &'static str, message: String, help: &str) -> Finding {
    Finding {
        rule,
        severity: Severity::Warning,
        package: Some(waiver.package.clone()),
        version: waiver.version.clone(),
        environment: String::new(),
        platform: String::new(),
        file: File::Policy,
        line: waiver.line,
        message,
        help: Some(help.into()),
        advisory: Vec::new(),
    }
}

/// Apply the policy's waivers to every finding of `outcome`, as of `today`, and report the waivers that are expired,
/// unused or too long.
pub fn apply(outcome: &mut Outcome, policy: &Policy, today: Date) {
    let waivers: Vec<&Waiver> = policy.waivers.iter().map(|w| w.get_ref()).collect();
    let expired = |waiver: &Waiver| waiver.expires_on() < today;
    let mut used = vec![false; waivers.len()];
    for finding in std::mem::take(&mut outcome.findings) {
        let live = waivers.iter().position(|w| !expired(w) && covers(w, &finding));
        match live {
            Some(index) => {
                used[index] = true;
                outcome.waived.push(Waived {
                    finding,
                    reason: waivers[index].reason.clone(),
                    expires: waivers[index].expires_on().to_string(),
                    vex: None,
                });
            }
            None => outcome.findings.push(finding),
        }
    }
    let max_days = policy.max_waiver_days.unwrap_or(MAX_WAIVER_DAYS);
    for (index, waiver) in waivers.iter().enumerate() {
        let expires = waiver.expires_on();
        let what = format!("waiver for {} on {}", waiver.rule, waiver.package);
        if expired(waiver) {
            outcome.findings.push(about(
                waiver,
                "waivers.expired",
                format!("{what} expired on {expires}; what it waived fails again"),
                "fix what it waived, or renew the waiver with a new expires date and a reason that still holds",
            ));
        } else if !used[index] {
            outcome.findings.push(about(
                waiver,
                "waivers.unused",
                format!("{what} matches no finding"),
                "remove the waiver, or correct its rule, package, version, environment or platform",
            ));
        }
        if max_days > 0 && expires.days() - today.days() > i64::from(max_days) {
            outcome.findings.push(about(
                waiver,
                "waivers.too-long",
                format!("{what} runs until {expires}, more than {max_days} days from today"),
                "bring expires closer, or raise max-waiver-days at the top of the policy",
            ));
        }
    }
    outcome.findings.sort_by(|a, b| {
        (a.severity, a.rule, &a.package, &a.environment, &a.platform).cmp(&(
            b.severity,
            b.rule,
            &b.package,
            &b.environment,
            &b.platform,
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(text: &str) -> Date {
        let value: toml::value::Datetime = text.parse().unwrap();
        Date::from_toml(&value).unwrap()
    }

    fn finding(rule: &'static str, package: &str, environment: &str) -> Finding {
        Finding {
            rule,
            severity: Severity::Error,
            package: Some(package.into()),
            version: Some("8.3".into()),
            environment: environment.into(),
            platform: "linux-64".into(),
            file: File::Lockfile,
            line: None,
            message: "denied".into(),
            help: None,
            advisory: Vec::new(),
        }
    }

    fn applied(policy: &str, findings: Vec<Finding>, today: &str) -> Outcome {
        let policy = Policy::parse(policy, "p.toml").unwrap();
        let mut outcome = Outcome {
            findings,
            ..Outcome::default()
        };
        apply(&mut outcome, &policy, date(today));
        outcome
    }

    const WAIVER: &str = "[[waivers]]\nrule = \"licenses.deny\"\npackage = \"readline\"\nreason = \"dev env only; LEGAL-1234\"\nexpires = 2027-03-31\n";

    #[test]
    fn a_waived_finding_is_reported_as_waived_and_does_not_fail() {
        let outcome = applied(
            WAIVER,
            vec![finding("licenses.deny", "readline", "default")],
            "2026-10-11",
        );
        assert!(
            outcome.findings.is_empty() && !outcome.failed(),
            "{:?}",
            outcome.findings
        );
        assert_eq!(outcome.waived.len(), 1);
        assert_eq!(outcome.waived[0].reason, "dev env only; LEGAL-1234");
        assert_eq!(outcome.waived[0].expires, "2027-03-31");
        // The last day still counts.
        assert_eq!(
            applied(
                WAIVER,
                vec![finding("licenses.deny", "readline", "default")],
                "2027-03-31"
            )
            .waived
            .len(),
            1
        );
    }

    #[test]
    fn an_expired_waiver_fails_again_and_is_reported() {
        let outcome = applied(
            WAIVER,
            vec![finding("licenses.deny", "readline", "default")],
            "2027-04-01",
        );
        assert!(outcome.waived.is_empty() && outcome.failed());
        let rules: Vec<&str> = outcome.findings.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["licenses.deny", "waivers.expired"]);
        let expired = &outcome.findings[1];
        assert_eq!(
            expired.message,
            "waiver for licenses.deny on readline expired on 2027-03-31; what it waived fails again"
        );
        assert_eq!(
            (expired.file, expired.line, expired.severity),
            (File::Policy, Some(1), Severity::Warning)
        );
    }

    #[test]
    fn an_unused_waiver_is_reported() {
        let outcome = applied(WAIVER, vec![finding("licenses.deny", "other", "default")], "2026-10-11");
        let rules: Vec<&str> = outcome.findings.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["licenses.deny", "waivers.unused"]);
    }

    #[test]
    fn a_waiver_can_be_narrowed_and_matches_names_in_any_case() {
        let narrow = WAIVER.replace(
            "expires",
            "environment = \"dev\"\nversion = \"8.3\"\nplatform = \"linux-64\"\nexpires",
        );
        let outcome = applied(
            &narrow,
            vec![
                finding("licenses.deny", "READLINE", "dev"),
                finding("licenses.deny", "readline", "default"),
            ],
            "2026-10-11",
        );
        assert_eq!(outcome.waived.len(), 1);
        assert_eq!(outcome.waived[0].finding.environment, "dev");
        assert_eq!(outcome.findings.len(), 1);
        let other_rule = applied(WAIVER, vec![finding("bans.deny", "readline", "default")], "2026-10-11");
        assert!(other_rule.waived.is_empty());
    }

    #[test]
    fn an_advisory_waiver_matches_the_id_or_any_alias() {
        let waiver = "[[waivers]]\nrule = \"advisories.vulnerable\"\npackage = \"urllib3\"\nadvisory = \"cve-2023-43804\"\n\
                      reason = \"r\"\nexpires = 2027-03-31\n";
        let advisory = |names: &[&str]| Finding {
            advisory: names.iter().map(|n| n.to_string()).collect(),
            ..finding("advisories.vulnerable", "urllib3", "default")
        };
        let outcome = applied(
            waiver,
            vec![advisory(&["GHSA-v845", "CVE-2023-43804"]), advisory(&["GHSA-other"])],
            "2026-10-11",
        );
        assert_eq!(outcome.waived.len(), 1);
        assert_eq!(outcome.waived[0].finding.advisory[0], "GHSA-v845");
        assert_eq!(outcome.findings.len(), 1);
    }

    #[test]
    fn a_waiver_too_far_out_is_reported_and_still_applies() {
        let long = WAIVER.replace("2027-03-31", "2099-12-31");
        let outcome = applied(
            &long,
            vec![finding("licenses.deny", "readline", "default")],
            "2026-10-11",
        );
        assert_eq!(outcome.waived.len(), 1);
        let rules: Vec<&str> = outcome.findings.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["waivers.too-long"]);
        assert!(!outcome.failed());
        let raised = format!("max-waiver-days = 40000\n{long}");
        assert!(
            applied(
                &raised,
                vec![finding("licenses.deny", "readline", "default")],
                "2026-10-11"
            )
            .findings
            .is_empty()
        );
        let off = format!("max-waiver-days = 0\n{long}");
        assert!(
            applied(
                &off,
                vec![finding("licenses.deny", "readline", "default")],
                "2026-10-11"
            )
            .findings
            .is_empty()
        );
        // 365 days exactly is within the limit.
        let year = WAIVER.replace("2027-03-31", "2027-10-11");
        assert!(
            applied(
                &year,
                vec![finding("licenses.deny", "readline", "default")],
                "2026-10-11"
            )
            .findings
            .is_empty()
        );
    }

    #[test]
    fn a_waiver_without_expires_or_with_an_unknown_rule_is_a_policy_error() {
        let missing = "[[waivers]]\nrule = \"licenses.deny\"\npackage = \"readline\"\nreason = \"x\"\n";
        let err = Policy::parse(missing, "p.toml").unwrap_err();
        assert!(err.to_string().contains("expires"), "{err}");
        let unknown = WAIVER.replace("licenses.deny", "licences.deny");
        let err = Policy::parse(&unknown, "p.toml").unwrap_err();
        assert!(
            err.to_string()
                .contains("\"licences.deny\", which pixi-policy does not have"),
            "{err}"
        );
        let time = WAIVER.replace("2027-03-31", "2027-03-31T10:00:00");
        let err = Policy::parse(&time, "p.toml").unwrap_err();
        assert!(err.to_string().contains("not a date"), "{err}");
        let no_reason = WAIVER.replace("reason = \"dev env only; LEGAL-1234\"\n", "");
        assert!(Policy::parse(&no_reason, "p.toml").is_err());
    }

    #[test]
    fn dates_convert_both_ways() {
        for text in [
            "1970-01-01",
            "2000-02-29",
            "2026-10-11",
            "2027-03-31",
            "2099-12-31",
            "1969-12-31",
        ] {
            let d = date(text);
            assert_eq!(Date::from_days(d.days()), d);
            assert_eq!(d.to_string(), text);
        }
        assert_eq!(date("1970-01-02").days(), 1);
        assert_eq!(date("2027-03-31").days() - date("2026-10-11").days(), 171);
        assert!(Date::today() > date("2026-01-01"));
    }
}
