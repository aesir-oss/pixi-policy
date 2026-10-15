//! VEX for `[advisories]` (#10): statements that an advisory does not affect a package, read from the files
//! `[advisories] vex` names (CycloneDX, as a VEX or as `vulnerabilities[].analysis` in an SBOM, or OpenVEX), the way
//! pixi-sbom's `--vex-in` reads them. A statement matches a finding by advisory id or alias and by the purl of the
//! package it names (one naming no product covers every package). `not_affected`, `false_positive` and the resolved
//! states move the finding to the waived ones with the statement; `exploitable` and `in_triage` leave it failing.
//! A later statement wins over an earlier one (decided on #10).

use std::collections::HashMap;

use miette::Diagnostic;
use rattler_lock::LockFile;
use serde_json::Value;
use thiserror::Error;

use crate::check::{Outcome, Waived};
use crate::fetch::{Remote, Settings};
use crate::lockfile::{self, Fact};
use crate::policy::Policy;

/// The CycloneDX impact-analysis states.
const STATES: [&str; 6] = [
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
];

/// The states that take a finding out of the check.
const SUPPRESSING: [&str; 4] = ["not_affected", "false_positive", "resolved", "resolved_with_pedigree"];

/// The CycloneDX impact-analysis justifications, given with `not_affected`.
const JUSTIFICATIONS: [&str; 9] = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
];

/// Why a VEX file could not be used.
#[derive(Debug, Error, Diagnostic)]
#[error("cannot use the VEX {location}: {message}")]
#[diagnostic(
    code(pixi_policy::vex),
    help(
        "[advisories] vex takes CycloneDX JSON (a VEX, or an SBOM with vulnerabilities) or OpenVEX, by a path relative \
         to the policy that names it or a pinned https URL"
    )
)]
pub struct VexError {
    pub location: String,
    pub message: String,
}

/// What a statement says about an advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// A CycloneDX state: `not_affected`, `resolved`, ...
    pub state: &'static str,
    /// Why it is not affected, with `not_affected`.
    pub justification: Option<&'static str>,
    pub detail: Option<String>,
    /// The file it came from, by name.
    pub source: String,
}

impl Analysis {
    /// `not_affected (code_not_reachable), vendor.cdx.json: the parser is never used`.
    pub fn describe(&self) -> String {
        let mut out = self.state.to_string();
        if let Some(justification) = self.justification {
            out.push_str(&format!(" ({justification})"));
        }
        out.push_str(&format!(", {}", self.source));
        if let Some(detail) = &self.detail {
            out.push_str(&format!(": {detail}"));
        }
        out
    }
}

/// One statement: which advisory, for which packages, and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The advisory id and its aliases, as the statement gives them.
    pub ids: Vec<String>,
    /// The purls of the packages it covers; empty means every package.
    pub products: Vec<String>,
    pub analysis: Analysis,
}

impl Statement {
    fn names(&self, advisory: &[String]) -> bool {
        advisory
            .iter()
            .any(|name| self.ids.iter().any(|id| id.eq_ignore_ascii_case(name)))
    }

    fn covers(&self, purls: &[String]) -> bool {
        self.products.is_empty()
            || self
                .products
                .iter()
                .any(|product| purls.iter().any(|purl| same_package(product, purl)))
    }
}

fn known(list: &[&'static str], word: &str) -> Option<&'static str> {
    list.iter().find(|w| **w == word).copied()
}

fn text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// The statements in a VEX document's `text`; `source` names it in the report.
pub fn parse(text: &str, source: &str) -> Result<Vec<Statement>, String> {
    let document: Value = serde_json::from_str(text).map_err(|err| format!("it is not JSON ({err})"))?;
    if document["bomFormat"] == "CycloneDX" {
        Ok(cyclonedx(&document, source))
    } else if document["statements"].is_array() {
        Ok(openvex(&document, source))
    } else {
        Err("it is neither a CycloneDX document nor OpenVEX".into())
    }
}

/// CycloneDX: every vulnerability with an `analysis`, its `affects[].ref` resolved through the document's components
/// when it is an SBOM, or read as a BOM-Link's fragment otherwise.
fn cyclonedx(document: &Value, source: &str) -> Vec<Statement> {
    let mut purls: HashMap<&str, &str> = HashMap::new();
    let mut stack: Vec<&Value> = document["components"].as_array().into_iter().flatten().collect();
    if document["metadata"]["component"].is_object() {
        stack.push(&document["metadata"]["component"]);
    }
    while let Some(component) = stack.pop() {
        if let (Some(reference), Some(purl)) = (component["bom-ref"].as_str(), component["purl"].as_str()) {
            purls.insert(reference, purl);
        }
        stack.extend(component["components"].as_array().into_iter().flatten());
    }
    let mut statements = Vec::new();
    for vuln in document["vulnerabilities"].as_array().into_iter().flatten() {
        let analysis = &vuln["analysis"];
        let (Some(id), Some(state)) = (text(&vuln["id"]), analysis["state"].as_str()) else {
            continue;
        };
        let Some(state) = known(&STATES, state) else {
            tracing::warn!(
                id,
                state,
                source,
                "skipping a VEX statement with an unknown analysis state"
            );
            continue;
        };
        let mut ids = vec![id];
        ids.extend(
            vuln["references"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| text(&r["id"])),
        );
        let products = vuln["affects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a["ref"].as_str())
            .map(|reference| {
                let local = reference.rsplit_once('#').map_or(reference, |(_, fragment)| fragment);
                purls
                    .get(reference)
                    .or_else(|| purls.get(local))
                    .copied()
                    .unwrap_or(local)
                    .to_string()
            })
            .collect();
        statements.push(Statement {
            ids,
            products,
            analysis: Analysis {
                state,
                justification: analysis["justification"]
                    .as_str()
                    .and_then(|j| known(&JUSTIFICATIONS, j))
                    .filter(|_| state == "not_affected"),
                detail: text(&analysis["detail"]),
                source: source.to_string(),
            },
        });
    }
    statements
}

/// OpenVEX: each statement's status and justification mapped onto the CycloneDX vocabulary; a product's
/// subcomponents, when it lists any, are the packages the statement is about.
fn openvex(document: &Value, source: &str) -> Vec<Statement> {
    let mut statements = Vec::new();
    for statement in document["statements"].as_array().into_iter().flatten() {
        let vulnerability = &statement["vulnerability"];
        // OpenVEX 0.0.x gave the vulnerability as a bare string.
        let Some(id) = text(vulnerability).or_else(|| text(&vulnerability["name"])) else {
            continue;
        };
        let mut ids = vec![id];
        ids.extend(
            vulnerability["aliases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(text),
        );
        let status = statement["status"].as_str().unwrap_or_default();
        let Some(state) = (match status {
            "not_affected" => Some("not_affected"),
            "fixed" => Some("resolved"),
            "affected" => Some("exploitable"),
            "under_investigation" => Some("in_triage"),
            _ => None,
        }) else {
            tracing::warn!(
                id = ids[0],
                status,
                source,
                "skipping an OpenVEX statement with an unknown status"
            );
            continue;
        };
        let justification = match statement["justification"].as_str().unwrap_or_default() {
            "component_not_present" | "vulnerable_code_not_present" => Some("code_not_present"),
            "vulnerable_code_not_in_execute_path" => Some("code_not_reachable"),
            "vulnerable_code_cannot_be_controlled_by_adversary" => Some("protected_at_runtime"),
            "inline_mitigations_already_exist" => Some("protected_by_mitigating_control"),
            _ => None,
        }
        .filter(|_| state == "not_affected");
        let identity = |product: &Value| {
            text(&product["identifiers"]["purl"])
                .or_else(|| text(&product["@id"]))
                .or_else(|| text(product))
        };
        let mut products = Vec::new();
        for product in statement["products"].as_array().into_iter().flatten() {
            let subcomponents: Vec<String> = product["subcomponents"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(identity)
                .collect();
            if subcomponents.is_empty() {
                products.extend(identity(product));
            } else {
                products.extend(subcomponents);
            }
        }
        let detail = ["impact_statement", "status_notes", "action_statement"]
            .iter()
            .find_map(|field| text(&statement[*field]));
        statements.push(Statement {
            ids,
            products,
            analysis: Analysis {
                state,
                justification,
                detail,
                source: source.to_string(),
            },
        });
    }
    statements
}

/// `pkg:type/name` (lower-cased, a PyPI name normalized) and the version, from a purl; `None` for something that is
/// not one.
fn package_key(purl: &str) -> Option<(String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let (path, version) = match rest.rsplit_once('@') {
        Some((path, version)) => (path, Some(version.to_string())),
        None => (rest, None),
    };
    let (kind, name) = path.split_once('/')?;
    let kind = kind.to_ascii_lowercase();
    let name = if kind == "pypi" {
        crate::purl::normalize_pypi_name(name)
    } else {
        name.to_ascii_lowercase()
    };
    Some((format!("pkg:{kind}/{name}"), version))
}

/// Whether a statement's product names the package with purl `purl`: the same package, and the same version when the
/// product gives one.
fn same_package(product: &str, purl: &str) -> bool {
    match (package_key(product), package_key(purl)) {
        (Some((product, version)), Some((package, package_version))) => {
            product == package && version.is_none_or(|v| package_version.is_some_and(|p| p == v))
        }
        _ => product == purl,
    }
}

/// The statements of every file `policy`'s `[advisories] vex` names, in order. Entries are paths or pinned URLs, made
/// so when the policy was read; a URL is fetched once and cached like an extended policy.
pub fn load(policy: &Policy, settings: &Settings) -> Result<Vec<Statement>, VexError> {
    let mut statements = Vec::new();
    for location in policy.advisories.iter().flat_map(|advisories| &advisories.vex) {
        let error = |message: String| VexError {
            location: location.clone(),
            message,
        };
        let text = if location.contains("://") {
            let remote = Remote {
                url: location.clone(),
                sha256: None,
            };
            crate::fetch::fetch(&remote, settings).map_err(error)?
        } else {
            std::fs::read_to_string(location).map_err(|err| error(err.to_string()))?
        };
        let source = location.rsplit(['/', '\\']).next().unwrap_or(location);
        statements.extend(parse(&text, source).map_err(error)?);
    }
    Ok(statements)
}

/// The purls an advisory finding about `fact` could be stated against: its own, and the PyPI ones it was looked up by.
fn purls(fact: &Fact, data: Option<&crate::advisories::Data>) -> Vec<String> {
    let mut out = vec![fact.purl.clone()];
    out.extend(fact.stated_purls.iter().cloned());
    out.extend(crate::advisories::identities(
        fact,
        data.and_then(|data| data.mapping.as_ref()),
    ));
    out
}

/// Move the `advisories.*` findings in `outcome` that a statement takes out of the check to the waived ones.
pub fn apply(outcome: &mut Outcome, statements: &[Statement], lock: &LockFile, data: Option<&crate::advisories::Data>) {
    if statements.is_empty() {
        return;
    }
    let mut facts: HashMap<(String, String), Vec<Fact>> = HashMap::new();
    for finding in std::mem::take(&mut outcome.findings) {
        let applies = (|| {
            if finding.advisory.is_empty() {
                return None;
            }
            let key = (finding.environment.clone(), finding.platform.clone());
            let packages = facts.entry(key).or_insert_with(|| {
                lockfile::read(lock, &finding.environment, Some(&finding.platform))
                    .map(|facts| facts.packages)
                    .unwrap_or_default()
            });
            let fact = packages
                .iter()
                .find(|fact| Some(&fact.name) == finding.package.as_ref() && fact.version == finding.version)?;
            let purls = purls(fact, data);
            statements
                .iter()
                .rev()
                .find(|statement| statement.names(&finding.advisory) && statement.covers(&purls))
                .map(|statement| statement.analysis.clone())
                .filter(|analysis| SUPPRESSING.contains(&analysis.state))
        })();
        match applies {
            Some(analysis) => outcome.waived.push(Waived {
                finding,
                reason: analysis.describe(),
                expires: String::new(),
                vex: Some(analysis),
            }),
            None => outcome.findings.push(finding),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclonedx_statements_resolve_their_references() {
        let text = r#"{"bomFormat":"CycloneDX","components":[{"bom-ref":"u","purl":"pkg:pypi/urllib3@1.26.4"}],
            "vulnerabilities":[
              {"id":"GHSA-1","references":[{"id":"CVE-1"}],"affects":[{"ref":"u"}],
               "analysis":{"state":"not_affected","justification":"code_not_reachable","detail":" never used "}},
              {"id":"GHSA-2","affects":[{"ref":"urn:cdx:x/1#pkg:pypi/idna@3.7"}],"analysis":{"state":"exploitable",
               "justification":"code_not_reachable"}},
              {"id":"GHSA-3"},
              {"id":"GHSA-4","analysis":{"state":"fine"}}]}"#;
        let statements = parse(text, "vendor.cdx.json").unwrap();
        assert_eq!(statements.len(), 2);
        assert_eq!(statements[0].ids, ["GHSA-1", "CVE-1"]);
        assert_eq!(statements[0].products, ["pkg:pypi/urllib3@1.26.4"]);
        assert_eq!(
            statements[0].analysis.describe(),
            "not_affected (code_not_reachable), vendor.cdx.json: never used"
        );
        assert_eq!(statements[1].products, ["pkg:pypi/idna@3.7"]);
        assert_eq!(statements[1].analysis.justification, None, "only with not_affected");
    }

    #[test]
    fn openvex_statements_map_onto_cyclonedx_states() {
        let text = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
            {"vulnerability":{"name":"CVE-1","aliases":["GHSA-1"]},"status":"not_affected",
             "justification":"vulnerable_code_not_in_execute_path",
             "products":[{"@id":"app","subcomponents":[{"@id":"pkg:pypi/urllib3@1.26.4"}]}]},
            {"vulnerability":"CVE-2","status":"fixed","products":[{"identifiers":{"purl":"pkg:pypi/jinja2"}}]},
            {"vulnerability":"CVE-3","status":"under_investigation","status_notes":"looking"},
            {"vulnerability":"CVE-4","status":"maybe"},
            {"status":"fixed"}]}"#;
        let statements = parse(text, "v.json").unwrap();
        assert_eq!(statements.len(), 3);
        assert_eq!(statements[0].products, ["pkg:pypi/urllib3@1.26.4"]);
        assert_eq!(statements[0].analysis.justification, Some("code_not_reachable"));
        assert_eq!(statements[1].analysis.state, "resolved");
        assert_eq!(statements[2].analysis.detail.as_deref(), Some("looking"));
        assert!(statements[2].products.is_empty());
        for (bad, wanted) in [("{", "not JSON"), (r#"{"spdxVersion":"SPDX-2.3"}"#, "neither")] {
            assert!(parse(bad, "x").unwrap_err().contains(wanted), "{bad}");
        }
    }

    #[test]
    fn a_url_is_read_from_the_cache_offline() {
        let url = "https://example.com/acme/v1/vex.json";
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            cache: Some(dir.path().to_path_buf()),
            offline: true,
        };
        let policy = Policy::parse(&format!("[advisories]\nvex = [\"{url}\"]\n"), "p.toml").unwrap();
        let err = load(&policy, &settings).unwrap_err();
        assert_eq!(err.location, url);
        std::fs::create_dir_all(dir.path().join("extends")).unwrap();
        std::fs::write(
            dir.path().join("extends").join(crate::fetch::sha256(url.as_bytes())),
            r#"{"statements":[{"vulnerability":"CVE-1","status":"not_affected"}]}"#,
        )
        .unwrap();
        let statements = load(&policy, &settings).unwrap();
        assert_eq!(statements[0].analysis.source, "vex.json");
    }

    #[test]
    fn purls_match_by_package_and_by_version_when_given() {
        assert!(same_package("pkg:pypi/urllib3@1.26.4", "pkg:pypi/urllib3@1.26.4"));
        assert!(same_package("pkg:pypi/urllib3", "pkg:pypi/urllib3@2.0.0"));
        assert!(same_package(
            "pkg:pypi/Typing_Extensions@4.0",
            "pkg:pypi/typing-extensions@4.0?x=y"
        ));
        assert!(!same_package("pkg:pypi/urllib3@1.26.5", "pkg:pypi/urllib3@1.26.4"));
        assert!(!same_package("pkg:pypi/urllib3", "pkg:conda/urllib3@1.26.4"));
        assert!(same_package("my-ref", "my-ref"));
        assert!(!same_package("pkg:pypi/urllib3@1", "my-ref"));
    }
}
