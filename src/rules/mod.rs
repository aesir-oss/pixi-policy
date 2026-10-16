//! The rule families. Each family's module defines its rules; [`all`] lists every one, in the order they run.

pub mod advisories;
pub mod bans;
pub mod freshness;
pub mod hygiene;
pub mod licenses;
pub mod lock;
pub mod manifest;
pub mod python;
pub mod sources;

use std::sync::Arc;

use crate::check::Rule;

/// Every rule, family by family.
pub fn all() -> Vec<Box<dyn Rule>> {
    with_data(None, None, None, None)
}

/// Every rule, the `advisories.*`, `freshness.*`, `hygiene.*` and `licenses.*` ones judging the data looked up for them.
pub fn with_data(
    advisories: Option<Arc<crate::advisories::Data>>,
    freshness: Option<Arc<freshness::Data>>,
    mapping: Option<Arc<crate::advisories::Mapping>>,
    wheels: Option<Arc<crate::wheel::Data>>,
) -> Vec<Box<dyn Rule>> {
    let mut rules = sources::rules();
    rules.extend(bans::rules());
    rules.extend(licenses::rules(wheels));
    rules.extend(advisories::rules(advisories));
    rules.extend(freshness::rules(freshness));
    rules.extend(python::rules());
    rules.extend(hygiene::rules(mapping));
    rules.extend(manifest::rules());
    rules.extend(lock::rules());
    rules
}
