//! The rule families. Each family's module defines its rules; [`all`] lists every one, in the order they run.

pub mod bans;
pub mod sources;

use crate::check::Rule;

/// Every rule, family by family.
pub fn all() -> Vec<Box<dyn Rule>> {
    let mut rules = sources::rules();
    rules.extend(bans::rules());
    rules
}
