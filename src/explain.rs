//! `pixi policy explain`: what each rule checks, its keys and an example (#68), then each key's type, allowed values
//! and default from the key reference (#70). The text before the keys is SARIF's rule help.

use crate::check::rules;

/// Every rule ID with its one-line summary: the policy's rules, then the findings about waivers.
pub fn catalog() -> Vec<(&'static str, &'static str)> {
    rules()
        .iter()
        .map(|rule| (rule.id(), rule.summary()))
        .chain(crate::waivers::RULES)
        .collect()
}

/// The keys and an example for each rule ID.
const DETAILS: &[(&str, &str)] = &[
    (
        "sources.channels",
        "Key: [sources] allowed-channels, a list of channel names or URLs. A name (\"conda-forge\") matches its \
         anaconda.org and prefix.dev URLs only; any other host is listed by URL. Mirrors are matched as the channel \
         they mirror, since pixi.lock records that channel.\n\n[sources]\nallowed-channels = [\"conda-forge\", \
         \"https://conda.example.com/prod\"]",
    ),
    (
        "sources.indexes",
        "Key: [sources] allowed-indexes, a list of PyPI index URLs (trailing slashes and host case do not matter). \
         pixi.lock records a wheel's index; one from the default index is checked against it.\n\n[sources]\n\
         allowed-indexes = [\"https://pypi.org/simple\"]",
    ),
    (
        "sources.git",
        "Key: [sources] allow-git (default: allowed). Set it to false to fail any package, conda (pixi-build) or \
         PyPI, that comes from a git repository.\n\n[sources]\nallow-git = false",
    ),
    (
        "sources.url",
        "Key: [sources] allow-url (default: allowed). Set it to false to fail any package that comes from a direct \
         URL: an archive, not a channel or an index.\n\n[sources]\nallow-url = false",
    ),
    (
        "sources.path",
        "Key: [sources] allow-path (default: allowed). Set it to false to fail any package that comes from a local \
         path, including a workspace package pixi builds from source.\n\n[sources]\nallow-path = false",
    ),
    (
        "bans.deny",
        "Key: [bans] deny, a list of bans: name, and optionally version (conda's rules for conda packages, PEP 440 \
         for PyPI ones), build (a conda build-string pattern), kind (\"conda\" or \"pypi\"), reason and use-instead. \
         A ban on a PyPI name also catches a conda package that provides it.\n\n[bans]\ndeny = [\n  { name = \
         \"pycrypto\", reason = \"unmaintained\", use-instead = \"pycryptodome\" },\n  { name = \"openssl\", version \
         = \"<3\", reason = \"EOL\" },\n]",
    ),
    (
        "licenses.deny",
        "Key: [licenses] deny, SPDX identifiers or patterns (\"GPL-3.0-*\"). A package fails when its license \
         cannot be satisfied without a denied license: MIT OR GPL-3.0-only passes, since MIT is an option. The \
         verdict is the one pixi-sbom's --deny-license gives.\n\n[licenses]\ndeny = [\"GPL-3.0-*\", \"AGPL-*\"]",
    ),
    (
        "licenses.review",
        "Key: [licenses] review, SPDX identifiers or patterns. A package that needs one is reported as a warning; \
         review licenses count as allowed for licenses.not-allowed.\n\n[licenses]\nreview = [\"LGPL-*\"]",
    ),
    (
        "licenses.not-allowed",
        "Key: [licenses] allow. When given, a package fails unless its license can be satisfied with allow and \
         review licenses alone. An -or-later requirement accepts later versions of the same license.\n\n\
         [licenses]\nallow = [\"MIT\", \"BSD-3-Clause\", \"Apache-2.0\"]",
    ),
    (
        "licenses.unknown",
        "Key: [licenses] unknown = \"warn\" (default), \"error\" or \"allow\": what a package with no license, or \
         one that is not an SPDX expression, gets. pixi.lock records no PyPI licenses, so every PyPI package is \
         unknown until pixi-policy reads license files.\n\n[licenses]\nunknown = \"error\"",
    ),
    (
        "manifest.wildcard-spec",
        "Key: [manifest] wildcard-spec (on once [manifest] exists). Fails a conda or PyPI dependency given as \"*\" \
         in any dependency table, at its line in the manifest.\n\n[manifest]\nwildcard-spec = true",
    ),
    (
        "manifest.python-pinned",
        "Key: [manifest] python-pinned (on once [manifest] exists). Fails a python dependency whose spec allows more \
         than one minor version (\">=3.10\"), or has none; \"3.12.*\" and \">=3.12,<3.13\" pass.\n\n[manifest]\n\
         python-pinned = true",
    ),
    (
        "manifest.required-platforms",
        "Key: [manifest] required-platforms, a list of platforms the workspace must list in [workspace] platforms.\
         \n\n[manifest]\nrequired-platforms = [\"linux-64\", \"osx-arm64\"]",
    ),
    (
        "lock.present",
        "Key: [lock] present (on once [lock] exists). Fails a workspace without a pixi.lock; without [lock], a \
         missing lockfile is an input error (exit 2) instead.\n\n[lock]\npresent = true",
    ),
    (
        "lock.complete",
        "Key: [lock] complete (on once [lock] exists). Fails an environment the manifest defines that pixi.lock does \
         not lock, or does not lock for one of its platforms.\n\n[lock]\ncomplete = true",
    ),
    (
        "lock.in-sync",
        "Key: [lock] in-sync (on once [lock] exists). Asks pixi, offline, whether pixi.lock still satisfies the \
         manifest (pixi list --locked); a warning when pixi cannot be run.\n\n[lock]\nin-sync = true",
    ),
    (
        "waivers.expired",
        "A [[waivers]] entry whose expires date has passed. What it waived fails again; renew it with a new date and \
         a reason that still holds, or fix the finding.\n\n[[waivers]]\nrule = \"licenses.deny\"\npackage = \
         \"readline\"\nreason = \"dev only; LEGAL-1234\"\nexpires = 2027-03-31",
    ),
    (
        "waivers.unused",
        "A [[waivers]] entry that matches no finding: its rule, package, version, environment or platform is wrong, \
         or the finding is gone. Remove it.\n\n[[waivers]]\nrule = \"bans.deny\"\npackage = \"pycrypto\"\nreason = \
         \"replaced in Q3\"\nexpires = 2027-01-31",
    ),
    (
        "waivers.too-long",
        "A [[waivers]] entry whose expires is more than max-waiver-days (default 365) away. The waiver still applies. \
         Set max-waiver-days at the top of the policy; 0 turns the check off.\n\nmax-waiver-days = 180",
    ),
];

/// The keys and an example for `id`.
pub fn details(id: &str) -> Option<&'static str> {
    DETAILS.iter().find(|(rule, _)| *rule == id).map(|(_, text)| *text)
}

/// The full explanation of `id`: the ID, its summary, what it checks with an example, then each of its keys with its
/// type, allowed values and default (#70).
pub fn text(id: &str) -> Option<String> {
    let (id, summary) = catalog().into_iter().find(|(rule, _)| *rule == id)?;
    Some(format!(
        "{id}: {summary}\n\n{}\n\n{}",
        details(id)?,
        crate::keys::explain(id)
    ))
}

/// Every rule, one per line, with its summary.
pub fn list() -> String {
    let catalog = catalog();
    let width = catalog.iter().map(|(id, _)| id.len()).max().unwrap_or(0);
    catalog
        .iter()
        .map(|(id, summary)| format!("{id:width$}  {summary}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_id_has_an_explain_text_and_every_text_a_rule() {
        let ids: Vec<&str> = catalog().iter().map(|(id, _)| *id).collect();
        for id in &ids {
            let text = text(id).unwrap_or_else(|| panic!("{id} has no explain text"));
            assert!(text.starts_with(&format!("{id}: ")), "{text}");
            let example = details(id)
                .unwrap()
                .split("\n\n")
                .nth(1)
                .unwrap_or_else(|| panic!("{id}: no example"));
            assert!(example.starts_with('[') || example.contains(" = "), "{id}: {example}");
        }
        for (id, _) in DETAILS {
            assert!(ids.contains(id), "{id} is explained but is not a rule");
        }
        assert_eq!(ids.len(), DETAILS.len());
    }

    #[test]
    fn each_example_is_a_valid_policy() {
        for (id, details) in DETAILS {
            let example = details.split("\n\n").nth(1).unwrap();
            crate::policy::Policy::parse(example, "example.toml").unwrap_or_else(|err| panic!("{id}: {err}"));
        }
    }

    #[test]
    fn unknown_ids_have_no_text_and_the_list_names_every_rule() {
        assert_eq!(text("licences.deny"), None);
        let list = list();
        assert_eq!(list.lines().count(), catalog().len());
        assert!(list.contains("bans.deny") && list.contains("waivers.too-long"));
    }
}
