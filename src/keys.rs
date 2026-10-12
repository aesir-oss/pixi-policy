//! Every key `pixi-policy.toml` accepts, with its type, allowed values, default, whether it is required and the rules
//! it drives (#70). `pixi policy explain <RULE>` prints the rows for a rule's keys, and the docs' policy reference is
//! generated from the same table; a test fails when the parser accepts a key this table does not list, or the table
//! lists one the parser rejects.

/// One key of the policy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// The table the key is in: `""` for the top level, `bans.deny` for a ban's fields, `waivers` for a waiver's.
    pub table: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
    pub values: &'static str,
    pub default: &'static str,
    pub required: bool,
    pub rules: &'static [&'static str],
    /// A TOML value for the key, which the tests parse to show the parser accepts it.
    pub example: &'static str,
}

impl Key {
    /// Whether the row is a table or list of tables that holds other keys (`[sources]`, `[[waivers]]`), not a key.
    pub fn is_container(&self) -> bool {
        self.table.is_empty() && (TABLES.contains(&self.name) || self.name == "waivers")
    }

    /// How the policy file writes the key: `max-waiver-days`, `[sources] allowed-channels`, `[bans] deny: name`,
    /// `[[waivers]] expires`, or a table on its own, `[sources]`.
    pub fn path(&self) -> String {
        match (self.table, self.name) {
            ("", name) if TABLES.contains(&name) => format!("[{name}]"),
            ("", "waivers") => "[[waivers]]".to_string(),
            ("", name) => name.to_string(),
            ("bans.deny", name) => format!("[bans] deny: {name}"),
            ("waivers", name) => format!("[[waivers]] {name}"),
            (table, name) => format!("[{table}] {name}"),
        }
    }
}

/// The rule-family tables.
const TABLES: &[&str] = &["sources", "bans", "licenses", "manifest", "lock"];

const SOURCES: &[&str] = &[
    "sources.channels",
    "sources.indexes",
    "sources.git",
    "sources.url",
    "sources.path",
];
const LICENSES: &[&str] = &[
    "licenses.deny",
    "licenses.review",
    "licenses.not-allowed",
    "licenses.unknown",
];
const MANIFEST: &[&str] = &[
    "manifest.wildcard-spec",
    "manifest.python-pinned",
    "manifest.required-platforms",
];
const LOCK: &[&str] = &["lock.present", "lock.complete", "lock.in-sync"];
const WAIVER_MATCH: &[&str] = &["waivers.unused"];

const WHEN_TABLE_EXISTS: &str = "true once the table exists; without the table the rule is off";

/// Every key, in the order the reference lists them.
pub const KEYS: &[Key] = &[
    Key {
        table: "",
        name: "sources",
        kind: "table",
        values: "the keys below",
        default: "absent: no source rule runs",
        required: false,
        rules: SOURCES,
        example: "{}",
    },
    Key {
        table: "sources",
        name: "allowed-channels",
        kind: "list of strings",
        values: "channel names or URLs. A name (\"conda-forge\") matches its anaconda.org and prefix.dev URLs; any other \
                 host is given by URL (\"https://conda.example.com/prod\"). Trailing slashes and host case do not \
                 matter",
        default: "not set: conda packages may come from any channel",
        required: false,
        rules: &["sources.channels"],
        example: "[\"conda-forge\"]",
    },
    Key {
        table: "sources",
        name: "allowed-indexes",
        kind: "list of strings",
        values: "PyPI index URLs (\"https://pypi.org/simple\"). Trailing slashes and host case do not matter",
        default: "not set: PyPI packages may come from any index",
        required: false,
        rules: &["sources.indexes"],
        example: "[\"https://pypi.org/simple\"]",
    },
    Key {
        table: "sources",
        name: "allow-git",
        kind: "boolean",
        values: "true, false",
        default: "true: packages may come from a git repository",
        required: false,
        rules: &["sources.git"],
        example: "false",
    },
    Key {
        table: "sources",
        name: "allow-url",
        kind: "boolean",
        values: "true, false",
        default: "true: packages may come from a direct URL",
        required: false,
        rules: &["sources.url"],
        example: "false",
    },
    Key {
        table: "sources",
        name: "allow-path",
        kind: "boolean",
        values: "true, false",
        default: "true: packages may come from a local path",
        required: false,
        rules: &["sources.path"],
        example: "false",
    },
    Key {
        table: "",
        name: "bans",
        kind: "table",
        values: "the keys below",
        default: "absent: nothing is banned",
        required: false,
        rules: &["bans.deny"],
        example: "{}",
    },
    Key {
        table: "bans",
        name: "deny",
        kind: "list of tables",
        values: "one table per ban, with the fields below",
        default: "[]: nothing is banned",
        required: false,
        rules: &["bans.deny"],
        example: "[]",
    },
    Key {
        table: "bans.deny",
        name: "name",
        kind: "string",
        values: "a package name. A PyPI name also catches a conda package that provides it",
        default: "none",
        required: true,
        rules: &["bans.deny"],
        example: "\"pycrypto\"",
    },
    Key {
        table: "bans.deny",
        name: "version",
        kind: "string",
        values: "a version range: conda's syntax for conda packages, PEP 440 for PyPI ones (\"<3\", \">=1.0,<1.1.1w\")",
        default: "not set: every version is banned",
        required: false,
        rules: &["bans.deny"],
        example: "\"<3\"",
    },
    Key {
        table: "bans.deny",
        name: "build",
        kind: "string",
        values: "a conda build-string pattern, with * matching any run of characters (\"*_cuda*\"); conda packages only",
        default: "not set: every build is banned",
        required: false,
        rules: &["bans.deny"],
        example: "\"*_cuda*\"",
    },
    Key {
        table: "bans.deny",
        name: "kind",
        kind: "string",
        values: "\"conda\", \"pypi\"",
        default: "not set: both kinds",
        required: false,
        rules: &["bans.deny"],
        example: "\"conda\"",
    },
    Key {
        table: "bans.deny",
        name: "reason",
        kind: "string",
        values: "any text; printed with the finding",
        default: "none",
        required: false,
        rules: &["bans.deny"],
        example: "\"unmaintained\"",
    },
    Key {
        table: "bans.deny",
        name: "use-instead",
        kind: "string",
        values: "any text; printed as the finding's fix hint",
        default: "none",
        required: false,
        rules: &["bans.deny"],
        example: "\"pycryptodome\"",
    },
    Key {
        table: "",
        name: "licenses",
        kind: "table",
        values: "the keys below",
        default: "absent: no license rule runs",
        required: false,
        rules: LICENSES,
        example: "{}",
    },
    Key {
        table: "licenses",
        name: "allow",
        kind: "list of strings",
        values: "SPDX license identifiers, or patterns with * expanded against the SPDX license list (\"LGPL-*\"). An \
                 -or-later entry accepts later versions of the same license",
        default: "[]: any license that is not denied is acceptable",
        required: false,
        rules: &["licenses.not-allowed"],
        example: "[\"MIT\", \"Apache-2.0\"]",
    },
    Key {
        table: "licenses",
        name: "review",
        kind: "list of strings",
        values: "SPDX license identifiers or patterns, as for allow",
        default: "[]",
        required: false,
        rules: &["licenses.review", "licenses.not-allowed"],
        example: "[\"LGPL-*\"]",
    },
    Key {
        table: "licenses",
        name: "deny",
        kind: "list of strings",
        values: "SPDX license identifiers or patterns, as for allow",
        default: "[]",
        required: false,
        rules: &["licenses.deny"],
        example: "[\"GPL-3.0-*\", \"AGPL-*\"]",
    },
    Key {
        table: "licenses",
        name: "unknown",
        kind: "string",
        values: "\"warn\", \"error\", \"allow\"",
        default: "\"warn\"",
        required: false,
        rules: &["licenses.unknown"],
        example: "\"error\"",
    },
    Key {
        table: "",
        name: "manifest",
        kind: "table",
        values: "the keys below",
        default: "absent: no manifest rule runs",
        required: false,
        rules: MANIFEST,
        example: "{}",
    },
    Key {
        table: "manifest",
        name: "wildcard-spec",
        kind: "boolean",
        values: "true, false",
        default: WHEN_TABLE_EXISTS,
        required: false,
        rules: &["manifest.wildcard-spec"],
        example: "true",
    },
    Key {
        table: "manifest",
        name: "python-pinned",
        kind: "boolean",
        values: "true, false",
        default: WHEN_TABLE_EXISTS,
        required: false,
        rules: &["manifest.python-pinned"],
        example: "true",
    },
    Key {
        table: "manifest",
        name: "required-platforms",
        kind: "list of strings",
        values: "pixi platform names (\"linux-64\", \"linux-aarch64\", \"osx-64\", \"osx-arm64\", \"win-64\", …)",
        default: "not set: no platform is required",
        required: false,
        rules: &["manifest.required-platforms"],
        example: "[\"linux-64\", \"osx-arm64\"]",
    },
    Key {
        table: "",
        name: "lock",
        kind: "table",
        values: "the keys below",
        default: "absent: no lock rule runs, and a missing pixi.lock is an input error (exit 2)",
        required: false,
        rules: LOCK,
        example: "{}",
    },
    Key {
        table: "lock",
        name: "present",
        kind: "boolean",
        values: "true, false",
        default: WHEN_TABLE_EXISTS,
        required: false,
        rules: &["lock.present"],
        example: "true",
    },
    Key {
        table: "lock",
        name: "complete",
        kind: "boolean",
        values: "true, false",
        default: WHEN_TABLE_EXISTS,
        required: false,
        rules: &["lock.complete"],
        example: "true",
    },
    Key {
        table: "lock",
        name: "in-sync",
        kind: "boolean",
        values: "true, false",
        default: WHEN_TABLE_EXISTS,
        required: false,
        rules: &["lock.in-sync"],
        example: "true",
    },
    Key {
        table: "",
        name: "max-waiver-days",
        kind: "integer",
        values: "0 or more: the furthest a waiver's expires may be from today, in days; 0 turns the check off",
        default: "365",
        required: false,
        rules: &["waivers.too-long"],
        example: "180",
    },
    Key {
        table: "",
        name: "waivers",
        kind: "list of tables",
        values: "one [[waivers]] table per exception, with the fields below",
        default: "absent: no exceptions",
        required: false,
        rules: &["waivers.expired", "waivers.unused", "waivers.too-long"],
        example: "[]",
    },
    Key {
        table: "waivers",
        name: "rule",
        kind: "string",
        values: "the ID of a policy rule, as `pixi policy explain` lists it (\"licenses.deny\"); waivers.* findings \
                 cannot be waived",
        default: "none",
        required: true,
        rules: WAIVER_MATCH,
        example: "\"licenses.deny\"",
    },
    Key {
        table: "waivers",
        name: "package",
        kind: "string",
        values: "the package's name, as the finding names it (case does not matter). Findings that name no package, \
                 such as the lock rules', cannot be waived",
        default: "none",
        required: true,
        rules: WAIVER_MATCH,
        example: "\"readline\"",
    },
    Key {
        table: "waivers",
        name: "version",
        kind: "string",
        values: "an exact version, as the finding names it",
        default: "not set: every version",
        required: false,
        rules: WAIVER_MATCH,
        example: "\"8.2\"",
    },
    Key {
        table: "waivers",
        name: "environment",
        kind: "string",
        values: "an environment name from pixi.toml",
        default: "not set: every environment",
        required: false,
        rules: WAIVER_MATCH,
        example: "\"default\"",
    },
    Key {
        table: "waivers",
        name: "platform",
        kind: "string",
        values: "a pixi platform name (\"linux-64\")",
        default: "not set: every platform",
        required: false,
        rules: WAIVER_MATCH,
        example: "\"linux-64\"",
    },
    Key {
        table: "waivers",
        name: "reason",
        kind: "string",
        values: "any text: why the exception is acceptable, and until when",
        default: "none",
        required: true,
        rules: &[],
        example: "\"dev only; LEGAL-1234\"",
    },
    Key {
        table: "waivers",
        name: "expires",
        kind: "date",
        values: "a TOML date, YYYY-MM-DD, unquoted: the last day the waiver applies",
        default: "none",
        required: true,
        rules: &["waivers.expired", "waivers.too-long"],
        example: "2027-03-31",
    },
];

/// The keys that drive `rule`, in reference order.
pub fn for_rule(rule: &str) -> Vec<&'static Key> {
    KEYS.iter().filter(|key| key.rules.contains(&rule)).collect()
}

/// The keys section of `pixi policy explain <RULE>`: each key with its type, allowed values and default.
pub fn explain(rule: &str) -> String {
    let keys: Vec<&Key> = for_rule(rule).into_iter().filter(|key| !key.is_container()).collect();
    if keys.is_empty() {
        return String::new();
    }
    let mut out = String::from("Keys:\n");
    for key in keys {
        let required = if key.required { ", required" } else { "" };
        out.push_str(&format!(
            "  {}  ({}{required})\n    values:  {}\n    default: {}\n",
            key.path(),
            key.kind,
            key.values,
            key.default
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    /// A policy with `key` set to its example, wrapped in whatever table it belongs to.
    fn policy_with(key: &Key) -> String {
        let ban = "name = \"x\"";
        let waiver = "rule = \"bans.deny\"\npackage = \"x\"\nreason = \"r\"\nexpires = 2027-01-01";
        match key.table {
            "" if key.name == "waivers" => format!("waivers = {}\n", key.example),
            "" => format!("{} = {}\n", key.name, key.example),
            "bans.deny" if key.name == "name" => format!("[[bans.deny]]\nname = {}\n", key.example),
            "bans.deny" => format!("[[bans.deny]]\n{ban}\n{} = {}\n", key.name, key.example),
            "waivers" => {
                let base: String = waiver
                    .lines()
                    .filter(|line| !line.starts_with(&format!("{} ", key.name)))
                    .map(|line| format!("{line}\n"))
                    .collect();
                format!("[[waivers]]\n{base}{} = {}\n", key.name, key.example)
            }
            table => format!("[{table}]\n{} = {}\n", key.name, key.example),
        }
    }

    /// The fields the parser accepts in `table`, read from its error for an unknown one.
    fn accepted(table: &str) -> Vec<String> {
        let text = match table {
            "" => "nope = 1\n".to_string(),
            "bans.deny" => "[[bans.deny]]\nname = \"x\"\nnope = 1\n".to_string(),
            "waivers" => "[[waivers]]\nnope = 1\n".to_string(),
            table => format!("[{table}]\nnope = 1\n"),
        };
        let err = Policy::parse(&text, "p.toml").unwrap_err().to_string();
        // serde says "expected one of `a`, `b`" for several fields and "expected `a`" for one.
        let expected = err
            .split("expected one of ")
            .nth(1)
            .or_else(|| err.split("expected ").nth(1))
            .unwrap_or_else(|| panic!("{table}: {err}"));
        expected
            .split(", ")
            .map(|field| field.trim().trim_matches('`').to_string())
            .collect()
    }

    #[test]
    fn every_listed_key_is_one_the_parser_accepts() {
        for key in KEYS {
            let text = policy_with(key);
            Policy::parse(&text, "p.toml").unwrap_or_else(|err| panic!("{}: {err}\n{text}", key.path()));
        }
    }

    #[test]
    fn every_key_the_parser_accepts_is_listed() {
        for table in [
            "",
            "sources",
            "bans",
            "bans.deny",
            "licenses",
            "manifest",
            "lock",
            "waivers",
        ] {
            let mut accepted = accepted(table);
            accepted.sort();
            let mut listed: Vec<String> = KEYS
                .iter()
                .filter(|key| key.table == table)
                .map(|key| key.name.to_string())
                .collect();
            listed.sort();
            assert_eq!(accepted, listed, "the keys of [{table}] and the reference disagree");
        }
    }

    #[test]
    fn every_rule_has_a_key_and_every_key_names_real_rules() {
        let ids: Vec<&str> = crate::explain::catalog().iter().map(|(id, _)| *id).collect();
        for id in &ids {
            assert!(!for_rule(id).is_empty(), "{id} has no key in the reference");
        }
        for key in KEYS {
            for rule in key.rules {
                assert!(ids.contains(rule), "{} names {rule}, which is not a rule", key.path());
            }
        }
    }

    #[test]
    fn required_fields_are_the_ones_the_parser_requires() {
        for key in KEYS.iter().filter(|key| key.required) {
            let text = policy_with(key);
            let without: String = text
                .lines()
                .filter(|line| !line.starts_with(&format!("{} = ", key.name)))
                .map(|line| format!("{line}\n"))
                .collect();
            assert!(
                Policy::parse(&without, "p.toml").is_err(),
                "{} is listed as required:\n{without}",
                key.path()
            );
        }
    }

    #[test]
    fn explain_names_each_key_with_its_type_values_and_default() {
        let text = explain("licenses.unknown");
        assert!(text.starts_with("Keys:\n  [licenses] unknown  (string)\n"), "{text}");
        assert!(text.contains("values:  \"warn\", \"error\", \"allow\"") && text.contains("default: \"warn\""));
        assert!(explain("waivers.expired").contains("[[waivers]] expires  (date, required)"));
        assert!(explain("nope").is_empty());
    }
}
