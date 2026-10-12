//! The report, in three formats: text for people, JSON for tools, SARIF for GitHub code scanning.

use std::fmt::Write;
use std::path::{Component, Path};

use anstyle::{AnsiColor, Style};
use clap::ValueEnum;
use common::style::Palette;
use serde_json::{Value, json};

use crate::check::{File, Finding, Outcome, Rule, Severity, Waived};

/// The version of the JSON report's shape; it changes only when a field is renamed or removed.
pub const JSON_VERSION: u32 = 1;

/// The output formats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Findings grouped by severity, then a summary line.
    #[default]
    Text,
    /// One object per finding with stable field names, plus the summary (schema: pixi-policy-report.schema.json).
    Json,
    /// SARIF 2.1.0, for GitHub code scanning.
    Sarif,
}

/// What the report is about, beyond the outcome.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub manifest: &'a Path,
    pub lockfile: &'a Path,
    pub policy: &'a Path,
    /// Paths in JSON and SARIF are given relative to this directory when they are inside it.
    pub base: &'a Path,
    /// Every rule pixi-policy has, for SARIF's rule list.
    pub rules: &'a [Box<dyn Rule>],
}

/// The report in `format`; `palette` colours only the text format.
pub fn render(format: Format, outcome: &Outcome, context: &Context<'_>, palette: Palette) -> String {
    match format {
        Format::Text => text(outcome, palette),
        Format::Json => pretty(&json(outcome, context)),
        Format::Sarif => pretty(&sarif(outcome, context)),
    }
}

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("a JSON value always serializes");
    text.push('\n');
    text
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

fn count(outcome: &Outcome, severity: Severity) -> usize {
    outcome.findings.iter().filter(|f| f.severity == severity).count()
}

/// `2 errors, 1 warning, 1 waived`.
fn tally(outcome: &Outcome) -> String {
    format!(
        "{}, {}, {} waived",
        plural(count(outcome, Severity::Error), "error"),
        plural(count(outcome, Severity::Warning), "warning"),
        outcome.waived.len()
    )
}

fn package(finding: &Finding) -> String {
    match (&finding.package, &finding.version) {
        (Some(name), Some(version)) => format!("{name} {version}: "),
        (Some(name), None) => format!("{name}: "),
        _ => String::new(),
    }
}

fn location(finding: &Finding) -> String {
    let file = match finding.line {
        Some(line) => format!("{}:{line}", finding.file),
        None => finding.file.to_string(),
    };
    match (finding.environment.is_empty(), finding.platform.is_empty()) {
        (true, _) => file,
        (false, true) => format!("{file}: environment {:?}", finding.environment),
        (false, false) => format!("{file}: environment {:?}, {}", finding.environment, finding.platform),
    }
}

/// The report people read: findings grouped by severity (errors first), the waived ones, then a summary line.
pub fn text(outcome: &Outcome, palette: Palette) -> String {
    let mut out = String::new();
    for finding in &outcome.findings {
        let style = match finding.severity {
            Severity::Error => Style::new().bold().fg_color(Some(AnsiColor::Red.into())),
            Severity::Warning => Style::new().bold().fg_color(Some(AnsiColor::Yellow.into())),
        };
        let head = palette.paint(style, &format!("{}[{}]", finding.severity, finding.rule));
        let _ = writeln!(out, "{head} {}{}", package(finding), finding.message);
        let _ = writeln!(out, "  {} {}", palette.dim("-->"), location(finding));
        if let Some(help) = &finding.help {
            let _ = writeln!(out, "  {} {help}", palette.dim("= help:"));
        }
        out.push('\n');
    }
    for Waived {
        finding,
        reason,
        expires,
    } in &outcome.waived
    {
        let line = format!(
            "waived[{}] {}{} ({}); waiver: {reason}, expires {expires}",
            finding.rule,
            package(finding),
            finding.message,
            location(finding)
        );
        let _ = writeln!(out, "{}", palette.dim(&line));
    }
    if !outcome.waived.is_empty() {
        out.push('\n');
    }
    let summary = format!(
        "{} in {} across {}",
        tally(outcome),
        plural(outcome.packages, "package"),
        plural(outcome.targets, "environment-platform pair"),
    );
    let _ = writeln!(out, "{}", palette.header(&summary));
    out
}

/// `path` relative to `base` with `/` separators when it is inside it, and whether it is.
fn relative(path: &Path, base: &Path) -> (String, bool) {
    match path.strip_prefix(base) {
        Ok(inside) => {
            let parts: Vec<String> = inside
                .components()
                .filter_map(|c| match c {
                    Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect();
            (parts.join("/"), true)
        }
        Err(_) => (path.display().to_string(), false),
    }
}

/// A path as a SARIF artifact location: relative to the source root when it is inside `base`, a `file:` URI otherwise.
fn artifact_location(path: &Path, base: &Path) -> Value {
    match relative(path, base) {
        (uri, true) => json!({ "uri": uri, "uriBaseId": "%SRCROOT%" }),
        (absolute, false) => {
            let slashed = absolute.replace('\\', "/");
            let uri = if slashed.starts_with('/') {
                format!("file://{slashed}")
            } else {
                format!("file:///{slashed}")
            };
            json!({ "uri": uri })
        }
    }
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "rule": finding.rule,
        "severity": finding.severity.to_string(),
        "package": finding.package,
        "version": finding.version,
        "environment": finding.environment,
        "platform": finding.platform,
        "file": finding.file.to_string(),
        "line": finding.line,
        "message": finding.message,
        "help": finding.help,
    })
}

/// The JSON report (schema: `crates/pixi-policy/schemas/pixi-policy-report.schema.json`).
pub fn json(outcome: &Outcome, context: &Context<'_>) -> Value {
    let path = |p: &Path| relative(p, context.base).0;
    json!({
        "version": JSON_VERSION,
        "tool": { "name": "pixi-policy", "version": env!("CARGO_PKG_VERSION") },
        "workspace": {
            "manifest": path(context.manifest),
            "lockfile": path(context.lockfile),
            "policy": path(context.policy),
        },
        "summary": {
            "passed": !outcome.failed(),
            "errors": count(outcome, Severity::Error),
            "warnings": count(outcome, Severity::Warning),
            "waived": outcome.waived.len(),
            "packages": outcome.packages,
            "targets": outcome.targets,
        },
        "findings": outcome.findings.iter().map(finding_json).collect::<Vec<_>>(),
        "waived": outcome.waived.iter().map(|waived| {
            let mut entry = finding_json(&waived.finding);
            entry["waiver"] = json!({ "reason": waived.reason, "expires": waived.expires });
            entry
        }).collect::<Vec<_>>(),
    })
}

/// A SARIF rule name: the ID in PascalCase (`bans.deny` -> `BansDeny`).
fn rule_name(id: &str) -> String {
    id.split(['.', '-', '_'])
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect::<String>())
                .unwrap_or_default()
        })
        .collect()
}

/// The SARIF 2.1.0 log: one run, a rule per rule ID, a result per finding (waived ones as suppressed results).
pub fn sarif(outcome: &Outcome, context: &Context<'_>) -> Value {
    let mut rules: Vec<(String, String)> = context
        .rules
        .iter()
        .map(|rule| (rule.id().to_string(), rule.summary().to_string()))
        .collect();
    for finding in outcome.findings.iter().chain(outcome.waived.iter().map(|w| &w.finding)) {
        if !rules.iter().any(|(id, _)| id == finding.rule) {
            rules.push((finding.rule.to_string(), finding.rule.to_string()));
        }
    }
    let result = |finding: &Finding, waived: Option<&Waived>| {
        let file = match finding.file {
            File::Lockfile => context.lockfile,
            File::Manifest | File::Pyproject => context.manifest,
            File::Policy => context.policy,
        };
        let mut physical = json!({ "artifactLocation": artifact_location(file, context.base) });
        if let Some(line) = finding.line {
            physical["region"] = json!({ "startLine": line });
        }
        let mut message = format!("{}{}", package(finding), finding.message);
        if let Some(help) = &finding.help {
            message.push_str(&format!(" Help: {help}"));
        }
        let mut location = json!({ "physicalLocation": physical });
        if let Some(name) = &finding.package {
            location["logicalLocations"] = json!([{ "name": name, "kind": "package" }]);
        }
        let mut result = json!({
            "ruleId": finding.rule,
            "ruleIndex": rules.iter().position(|(id, _)| id == finding.rule).expect("every finding's rule is listed"),
            "level": finding.severity.to_string(),
            "message": { "text": message },
            "locations": [location],
            "partialFingerprints": {
                "pixi-policy/finding": format!(
                    "{}|{}|{}|{}",
                    finding.rule,
                    finding.package.as_deref().unwrap_or(""),
                    finding.environment,
                    finding.platform
                ),
            },
            "properties": {
                "package": finding.package,
                "version": finding.version,
                "environment": finding.environment,
                "platform": finding.platform,
            },
        });
        if let Some(waived) = waived {
            result["suppressions"] = json!([{
                "kind": "external",
                "status": "accepted",
                "justification": waived.reason,
                "properties": { "expires": waived.expires },
            }]);
        }
        result
    };
    let results: Vec<Value> = outcome
        .findings
        .iter()
        .map(|f| result(f, None))
        .chain(outcome.waived.iter().map(|w| result(&w.finding, Some(w))))
        .collect();
    let rules: Vec<Value> = rules
        .iter()
        .map(|(id, summary)| {
            json!({
                "id": id,
                "name": rule_name(id),
                "shortDescription": { "text": summary },
                "helpUri": "https://aesir-oss.github.io/pixi-ext-contrib/",
            })
        })
        .collect();
    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pixi-policy",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://aesir-oss.github.io/pixi-ext-contrib/",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "passed": !outcome.failed(),
                "packages": outcome.packages,
                "targets": outcome.targets,
            },
        }],
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    struct Deny;

    impl Rule for Deny {
        fn id(&self) -> &'static str {
            "bans.deny"
        }
        fn summary(&self) -> &'static str {
            "Packages the policy never allows"
        }
        fn check(&self, _: &crate::policy::Policy, _: &common::lockfile::Facts) -> Vec<Finding> {
            Vec::new()
        }
    }

    fn finding(rule: &'static str, severity: Severity, package: &str, file: File, line: Option<u32>) -> Finding {
        Finding {
            rule,
            severity,
            package: Some(package.into()),
            version: Some("2.6.1".into()),
            environment: "default".into(),
            platform: "linux-64".into(),
            file,
            line,
            message: "is denied (unmaintained)".into(),
            help: Some("use pycryptodome instead".into()),
        }
    }

    fn sample() -> Outcome {
        Outcome {
            findings: vec![
                finding("bans.deny", Severity::Error, "pycrypto", File::Lockfile, None),
                finding("bans.deny", Severity::Error, "pycrypto2", File::Lockfile, None),
                Finding {
                    package: None,
                    version: None,
                    help: None,
                    message: "the lockfile is older than the manifest".into(),
                    ..finding("lock.fresh", Severity::Warning, "", File::Manifest, Some(12))
                },
            ],
            waived: vec![Waived {
                finding: finding("bans.deny", Severity::Error, "legacy", File::Lockfile, None),
                reason: "vendored; LEGAL-1234".into(),
                expires: "2027-03-31".into(),
            }],
            targets: 2,
            packages: 40,
        }
    }

    fn paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join("repo");
        (
            base.join("app/pixi.toml"),
            base.join("app/pixi.lock"),
            base.join("app/pixi-policy.toml"),
            base,
        )
    }

    fn schema_validator(file: &str) -> jsonschema::Validator {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        jsonschema::options().offline().build(&schema).unwrap()
    }

    fn assert_valid(validator: &jsonschema::Validator, doc: &Value) {
        let errors: Vec<String> = validator
            .iter_errors(doc)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{errors:#?}\n{doc:#}");
    }

    #[test]
    fn the_text_report() {
        insta::assert_snapshot!(text(&sample(), Palette::new(false)));
        insta::assert_snapshot!("text_empty", text(&Outcome::default(), Palette::new(false)));
    }

    #[test]
    fn colour_marks_the_severity_and_dims_the_rest() {
        let coloured = text(&sample(), Palette::new(true));
        assert!(coloured.contains("\u{1b}[1m\u{1b}[31merror[bans.deny]"), "{coloured:?}");
        assert!(coloured.contains("\u{1b}[33mwarning[lock.fresh]"), "{coloured:?}");
        assert!(coloured.contains("\u{1b}[2m-->"), "{coloured:?}");
    }

    #[test]
    fn the_json_report_matches_its_schema() {
        let (manifest, lockfile, policy, base) = paths();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(Deny)];
        let context = Context {
            manifest: &manifest,
            lockfile: &lockfile,
            policy: &policy,
            base: &base,
            rules: &rules,
        };
        let validator = schema_validator("schemas/pixi-policy-report.schema.json");
        for outcome in [sample(), Outcome::default()] {
            assert_valid(&validator, &json(&outcome, &context));
        }
        let doc = json(&sample(), &context);
        assert_eq!(doc["workspace"]["lockfile"], "app/pixi.lock");
        assert_eq!(
            doc["summary"],
            json!({"passed": false, "errors": 2, "warnings": 1, "waived": 1, "packages": 40, "targets": 2})
        );
        assert_eq!(doc["findings"][2]["line"], 12);
        assert_eq!(doc["findings"][2]["package"], Value::Null);
        assert_eq!(doc["waived"][0]["package"], "legacy");
        assert_eq!(
            doc["waived"][0]["waiver"],
            json!({"reason": "vendored; LEGAL-1234", "expires": "2027-03-31"})
        );
        let mut stripped = doc.clone();
        stripped["waived"][0].as_object_mut().unwrap().remove("waiver");
        assert!(!validator.is_valid(&stripped), "a waived finding needs its waiver");
        let mut extra = doc.clone();
        extra["findings"][0]["surprise"] = json!(1);
        assert!(!validator.is_valid(&extra), "a finding has no other fields");
        assert!(render(Format::Json, &sample(), &context, Palette::new(true)).ends_with("}\n"));
    }

    #[test]
    fn the_sarif_report_matches_the_sarif_schema() {
        let (manifest, lockfile, policy, base) = paths();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(Deny)];
        let context = Context {
            manifest: &manifest,
            lockfile: &lockfile,
            policy: &policy,
            base: &base,
            rules: &rules,
        };
        let validator = schema_validator("../pixi-sbom/tests/schemas/sarif-schema-2.1.0.json");
        for outcome in [sample(), Outcome::default()] {
            assert_valid(&validator, &sarif(&outcome, &context));
        }
        let doc = sarif(&sample(), &context);
        let run = &doc["runs"][0];
        let ids: Vec<&str> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            ["bans.deny", "lock.fresh"],
            "the catalog's rules, then any other a finding names"
        );
        assert_eq!(run["tool"]["driver"]["rules"][1]["name"], "LockFresh");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"],
            json!({"uri": "app/pixi.lock", "uriBaseId": "%SRCROOT%"})
        );
        assert_eq!(results[2]["ruleIndex"], 1);
        assert_eq!(
            results[2]["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert!(results[2]["locations"][0].get("logicalLocations").is_none());
        assert_eq!(results[3]["suppressions"][0]["kind"], "external");
        assert_eq!(results[3]["suppressions"][0]["justification"], "vendored; LEGAL-1234");
        assert_eq!(results[3]["suppressions"][0]["properties"]["expires"], "2027-03-31");
        assert!(render(Format::Sarif, &Outcome::default(), &context, Palette::new(false)).contains("\"2.1.0\""));
    }

    #[test]
    fn a_path_outside_the_base_is_a_file_uri() {
        let base = std::env::temp_dir().join("repo");
        let elsewhere = std::env::temp_dir().join("other").join("pixi.lock");
        let location = artifact_location(&elsewhere, &base);
        assert!(location["uri"].as_str().unwrap().starts_with("file:///"), "{location}");
        assert!(location.get("uriBaseId").is_none());
        assert_eq!(rule_name("manifest.no-star-pins"), "ManifestNoStarPins");
    }
}
