//! The rule families. Each family's module defines its rules; [`all`] lists every one, in the order they run.

pub mod advisories;
pub mod bans;
pub mod licenses;
pub mod lock;
pub mod manifest;
pub mod sources;

use std::sync::Arc;

use crate::check::Rule;

/// Every rule, family by family.
pub fn all() -> Vec<Box<dyn Rule>> {
    with_advisories(None)
}

/// Every rule, the `advisories.*` ones judging `data`.
pub fn with_advisories(data: Option<Arc<crate::advisories::Data>>) -> Vec<Box<dyn Rule>> {
    let mut rules = sources::rules();
    rules.extend(bans::rules());
    rules.extend(licenses::rules());
    rules.extend(advisories::rules(data));
    rules.extend(manifest::rules());
    rules.extend(lock::rules());
    rules
}
