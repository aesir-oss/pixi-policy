//! The policy reference and the rule catalog in pixi-policy's docs are generated from the code (#70): the key table
//! (`pixi_policy::keys::KEYS`) and the text `pixi policy explain` prints. These tests fail when a page and the code
//! disagree; `pixi run policy-docs` rewrites both pages.

use std::path::PathBuf;

use pixi_policy::keys::{KEYS, Key};

const REFERENCE: &str = "docs/reference.md";
const RULES: &str = "docs/rules.md";
const GENERATED: &str = "<!-- Generated from the code by `pixi run policy-docs`; edit crates/pixi-policy/src/keys.rs or \
                         src/explain.rs instead. -->";

/// The reference's sections: an anchor, a heading, and the table each one's keys come from.
const SECTIONS: &[(&str, &str, &str, Option<&str>)] = &[
    ("top-level", "Top-level keys", "", None),
    ("policy", "`[policy]`", "policy", Some("policy")),
    ("sources", "`[sources]`", "sources", Some("sources")),
    ("bans", "`[bans]`", "bans", Some("bans")),
    ("licenses", "`[licenses]`", "licenses", Some("licenses")),
    ("manifest", "`[manifest]`", "manifest", Some("manifest")),
    ("lock", "`[lock]`", "lock", Some("lock")),
    ("waivers", "`[[waivers]]`", "waivers", Some("waivers")),
];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Text for a Markdown table cell: `*` and `|` would otherwise be read as emphasis and a column break.
fn cell(text: &str) -> String {
    text.replace('*', "\\*").replace('|', "\\|")
}

fn rule_anchor(rule: &str) -> String {
    rule.replace('.', "-")
}

fn section_of(key: &Key) -> &'static str {
    match key.table {
        "" if key.name == "waivers" => "waivers",
        "" => "top-level",
        "bans.deny" => "bans",
        table => SECTIONS
            .iter()
            .find(|(_, _, t, _)| *t == table)
            .map_or("top-level", |(anchor, ..)| anchor),
    }
}

fn reference() -> String {
    let mut out = format!(
        "{GENERATED}\n\n# Policy file reference\n\nEvery key `pixi-policy.toml` accepts. A key the table does not list \
         is an error, so a misspelt key cannot quietly check nothing. `pixi policy explain <RULE>` prints the rows for \
         one rule's keys. The When extended column says how a key combines when one policy extends another; see \
         [Sharing a policy](extends.md).\n"
    );
    for (anchor, heading, table, container) in SECTIONS {
        out.push_str(&format!("\n## {heading} {{#{anchor}}}\n\n"));
        if let Some(name) = container {
            let key = KEYS
                .iter()
                .find(|key| key.table.is_empty() && key.name == *name)
                .unwrap();
            out.push_str(&format!(
                "A {}. When it is left out: {}.\n\n",
                key.kind,
                key.default.replace("absent: ", "")
            ));
        }
        let rows: Vec<&Key> = KEYS
            .iter()
            .filter(|key| {
                !key.is_container() && (key.table == *table || (*table == "bans" && key.table == "bans.deny"))
            })
            .collect();
        out.push_str(
            "| Key | Type | Allowed values | Default | Required | When extended | Rules |\n|---|---|---|---|---|---|---|\n",
        );
        for key in rows {
            let rules: Vec<String> = key
                .rules
                .iter()
                .map(|rule| format!("[`{rule}`](rules.md#{})", rule_anchor(rule)))
                .collect();
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                key.path(),
                key.kind,
                cell(key.values),
                cell(key.default),
                if key.required { "yes" } else { "no" },
                key.merge.describe(),
                if rules.is_empty() {
                    "–".to_string()
                } else {
                    rules.join(", ")
                }
            ));
        }
    }
    out
}

fn rules() -> String {
    let mut out = format!(
        "{GENERATED}\n\n# Rules\n\nEvery rule `pixi policy check` runs, with the text `pixi policy explain <RULE>` \
         prints. Each rule's keys are in the [policy file reference](reference.md).\n\n| Rule | Checks |\n|---|---|\n"
    );
    let catalog = pixi_policy::explain::catalog();
    for (id, summary) in &catalog {
        out.push_str(&format!("| [`{id}`](#{}) | {} |\n", rule_anchor(id), cell(summary)));
    }
    for (id, summary) in &catalog {
        let details = pixi_policy::explain::details(id).unwrap();
        let (prose, example) = details.split_once("\n\n").unwrap();
        out.push_str(&format!(
            "\n## `{id}` {{#{}}}\n\n{summary}.\n\n{prose}\n\n```toml\n{example}\n```\n",
            rule_anchor(id)
        ));
        let keys: Vec<String> = pixi_policy::keys::for_rule(id)
            .into_iter()
            .filter(|key| !key.is_container())
            .map(|key| format!("[`{}`](reference.md#{})", key.path(), section_of(key)))
            .collect();
        out.push_str(&format!("\nKeys: {}.\n", keys.join(", ")));
    }
    out
}

/// Compare `page` with `expected`, or write it when PIXI_POLICY_WRITE_DOCS is set.
fn check(page: &str, expected: &str) {
    let path = crate_dir().join(page);
    if std::env::var_os("PIXI_POLICY_WRITE_DOCS").is_some() {
        std::fs::write(&path, expected).unwrap();
        return;
    }
    let actual = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
    assert!(
        actual == expected,
        "crates/pixi-policy/{page} is out of date with the code: run `pixi run policy-docs`"
    );
}

#[test]
fn the_policy_reference_is_generated_from_the_key_table() {
    check(REFERENCE, &reference());
}

#[test]
fn the_rule_catalog_is_generated_from_the_explain_text() {
    check(RULES, &rules());
}

#[test]
fn every_rule_and_key_appears_in_the_pages() {
    let (reference, rules) = (reference(), rules());
    for (id, _) in pixi_policy::explain::catalog() {
        assert!(
            rules.contains(&format!("## `{id}`")),
            "{id} has no section in the rule catalog"
        );
    }
    for key in KEYS.iter().filter(|key| !key.is_container()) {
        assert!(
            reference.contains(&format!("| `{}` |", key.path())),
            "{} is not in the reference",
            key.path()
        );
    }
}
